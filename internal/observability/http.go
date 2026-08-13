package observability

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

var errHTTPSpan = errors.New("http request failed")

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *statusResponseWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusResponseWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(value)
}

func (writer *statusResponseWriter) Flush() {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	if flusher, ok := writer.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func HTTPHandler(tracer *Tracer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if tracer == nil || next == nil || request == nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx := ContextWithTracer(request.Context(), tracer)
		_, found := TraceFromContext(ctx)
		if !found {
			if trace, err := ExtractTrace(request.Header); err == nil {
				ctx, _ = ContextWithTrace(ctx, trace)
			}
		}
		name, route, correlation := httpSpan(request)
		if name == "" {
			next.ServeHTTP(response, request.WithContext(ctx))
			return
		}
		ctx, span := StartSpan(ctx, name, correlation, map[string]string{"http.request.method": request.Method, "http.route": route})
		if current, ok := TraceFromContext(ctx); ok {
			_ = InjectTrace(response.Header(), current)
		}
		tracked := &statusResponseWriter{ResponseWriter: response}
		next.ServeHTTP(tracked, request.WithContext(ctx))
		status := tracked.status
		if status == 0 {
			status = http.StatusOK
		}
		var operationErr error
		if status >= http.StatusBadRequest {
			operationErr = errHTTPSpan
		}
		EndSpan(ctx, span, operationErr, TraceOutcome{SecurityDenied: status == http.StatusUnauthorized || status == http.StatusForbidden}, map[string]string{"http.response.status_code": strconv.Itoa(status)})
	})
}

func httpSpan(request *http.Request) (string, string, Correlation) {
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	projectID := segmentAfter(segments, "projects")
	taskID := segmentAfter(segments, "tasks")
	correlation := Correlation{ProjectID: projectID, WorkflowIDReason: ReasonUnavailable, TaskID: taskID, AgentRunIDReason: ReasonNotCreated}
	if projectID == "" {
		correlation.ProjectIDReason = ReasonNotCreated
	}
	if taskID == "" {
		correlation.TaskIDReason = ReasonNotCreated
	}
	path := request.URL.Path
	switch {
	case request.Method == http.MethodPost && path == "/v1/projects":
		return SpanProjectCreate, "/v1/projects", correlation
	case request.Method == http.MethodPost && strings.Contains(path, "/knowledge:search"):
		return SpanKnowledgeSearch, "/v1/projects/{project}/knowledge/search", correlation
	case request.Method == http.MethodPost && strings.Contains(path, "/knowledge:read-range"):
		return SpanKnowledgeRead, "/v1/projects/{project}/knowledge/range", correlation
	case request.Method == http.MethodPost && (strings.Contains(path, ":approve") || strings.Contains(path, "/approvals")):
		return SpanApprovalCommit, "/v1/projects/{project}/approvals", correlation
	case request.Method == http.MethodPost && (strings.Contains(path, "/goal/") || strings.Contains(path, "/goal:")):
		return SpanGoalTurn, "/v1/projects/{project}/goal", correlation
	case strings.Contains(path, "/plans") && request.Method != http.MethodGet:
		return SpanPlanGenerate, "/v1/projects/{project}/plans", correlation
	default:
		return "", "", Correlation{}
	}
}

func segmentAfter(segments []string, key string) string {
	for index := 0; index+1 < len(segments); index++ {
		if segments[index] == key {
			return segments[index+1]
		}
	}
	return ""
}
