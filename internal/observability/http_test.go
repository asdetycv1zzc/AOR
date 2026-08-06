package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPHandlerStartsRootForKnowledgeSearch(t *testing.T) {
	sink := &MemoryTraceSink{Destination: "otlp://traces"}
	tracer, err := NewTracer(sink, RetentionSampler{NormalRate: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	projectID := "22222222-2222-4222-8222-222222222222"
	handler := HTTPHandler(tracer, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if _, found := TraceFromContext(request.Context()); !found {
			t.Fatal("request trace context is missing")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/knowledge:search", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || len(sink.Spans) != 1 {
		t.Fatalf("status=%d spans=%d", response.Code, len(sink.Spans))
	}
	span := sink.Spans[0]
	if span.Name != SpanKnowledgeSearch || span.ParentSpanID != "" || span.Attributes["aor.project.id"] != projectID {
		t.Fatalf("span = %#v", span)
	}
	propagated, err := ParseTraceParent(response.Header().Get(TraceParentHeader), response.Header().Get(TraceStateHeader))
	if err != nil || propagated.TraceID != span.TraceID || propagated.SpanID != span.SpanID {
		t.Fatalf("response trace = %#v, err=%v", propagated, err)
	}
}
