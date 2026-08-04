package orchestrator

import (
	"context"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/observability"
)

func TestApplyEventTracePropagatesContextAndProvidesStableFallback(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	events := []eventing.DomainEvent{{}, {}}
	applyEventTrace(context.Background(), digest, events)
	if events[0].Traceparent == "" || events[0].Traceparent != events[1].Traceparent || events[0].Traceparent != fallbackTraceParent(digest) {
		t.Fatalf("fallback trace context = %#v", events)
	}

	trace := observability.TraceContext{TraceID: "11111111111111111111111111111111", SpanID: "2222222222222222", TraceFlags: 1, TraceState: "vendor=value"}
	ctx, err := observability.ContextWithTrace(context.Background(), trace)
	if err != nil {
		t.Fatal(err)
	}
	applyEventTrace(ctx, digest, events)
	if events[0].Traceparent != "00-11111111111111111111111111111111-2222222222222222-01" || events[0].Tracestate != "vendor=value" {
		t.Fatalf("propagated trace context = %#v", events[0])
	}
}
