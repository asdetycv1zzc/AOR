package controlapi

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const curatorForwardedHeader = "X-AOR-Forwarded-By"

const maximumCuratorResponseBytes = 2 * maximumRequestBytes

func newKnowledgeCuratorHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validateKnowledgeCuratorURL(value string) error {
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00\\") {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge curator URL"})
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || strings.Contains(parsed.Path, "..") {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge curator URL"})
	}
	return nil
}

func isKnowledgeCuratorRequest(request *http.Request) bool {
	if request == nil || (request.Method != http.MethodGet && request.Method != http.MethodPost) {
		return false
	}
	parts, ok := splitProjectPath(request.URL.Path)
	if !ok {
		return false
	}
	if len(parts) == 2 && parts[1] == "knowledge:propose-update" {
		return request.Method == http.MethodPost && validProjectID(parts[0])
	}
	if len(parts) != 4 || parts[1] != "knowledge" || parts[2] != "updates" || !validProjectID(parts[0]) {
		return false
	}
	updateID, action, hasAction := strings.Cut(parts[3], ":")
	if !validArtifactID(updateID) {
		return false
	}
	if !hasAction {
		return request.Method == http.MethodGet
	}
	return action == "approve" && request.Method == http.MethodPost
}

func (handler *Handler) proxyKnowledgeCurator(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get(curatorForwardedHeader) != "" {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge curator proxy loop"}))
		return
	}
	target := handler.knowledgeCuratorURL + request.URL.RequestURI()
	forward, err := http.NewRequestWithContext(request.Context(), request.Method, target, request.Body)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge curator proxy"}))
		return
	}
	for _, name := range []string{"Accept", "Authorization", "Content-Type", "Idempotency-Key", "If-Match", "Traceparent", "Tracestate", "X-Request-ID"} {
		values := request.Header.Values(name)
		for _, value := range values {
			forward.Header.Add(name, value)
		}
	}
	forward.Header.Set(curatorForwardedHeader, "aor-api")
	client := handler.knowledgeCuratorHTTP
	if client == nil {
		client = http.DefaultClient
	}
	remote, err := client.Do(forward)
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "knowledge curator proxy"}))
		return
	}
	defer remote.Body.Close()
	body, err := io.ReadAll(io.LimitReader(remote.Body, maximumCuratorResponseBytes+1))
	if err != nil || len(body) > maximumCuratorResponseBytes {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge curator response"}))
		return
	}
	for _, name := range []string{"Cache-Control", "Content-Type", "ETag", "Location", "X-Request-ID"} {
		if value := remote.Header.Get(name); value != "" {
			response.Header().Set(name, value)
		}
	}
	response.WriteHeader(remote.StatusCode)
	_, _ = response.Write(body)
}
