package servicebootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akimisaka/aor/internal/observability"
)

func TestWithRequestTracePropagatesValidHeaderAndReplacesMalformedHeader(t *testing.T) {
	seen := make(chan observability.TraceContext, 2)
	handler := withRequestTrace(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		trace, found := observability.TraceFromContext(request.Context())
		if !found {
			t.Fatal("trace context was not attached")
		}
		seen <- trace
		response.WriteHeader(http.StatusNoContent)
	}))

	valid := httptest.NewRequest(http.MethodGet, "/", nil)
	valid.Header.Set(observability.TraceParentHeader, "00-11111111111111111111111111111111-2222222222222222-01")
	valid.Header.Set(observability.TraceStateHeader, "vendor=value")
	handler.ServeHTTP(httptest.NewRecorder(), valid)
	propagated := <-seen
	if propagated.TraceID != "11111111111111111111111111111111" || propagated.SpanID != "2222222222222222" || propagated.TraceState != "vendor=value" {
		t.Fatalf("propagated trace = %#v", propagated)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/", nil)
	malformed.Header.Set(observability.TraceParentHeader, "forged\r\ntrace")
	handler.ServeHTTP(httptest.NewRecorder(), malformed)
	replaced := <-seen
	if replaced.Validate() != nil || replaced.TraceID == propagated.TraceID {
		t.Fatalf("replacement trace = %#v", replaced)
	}
}
