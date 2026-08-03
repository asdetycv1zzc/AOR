package observability

import (
	"context"
	"errors"
	"testing"
)

func TestW3CTraceContextRoundTrip(t *testing.T) {
	parent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	parsed, err := ParseTraceParent(parent, "vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	carrier := MapCarrier{}
	if err := InjectTrace(carrier, parsed); err != nil {
		t.Fatal(err)
	}
	extracted, err := ExtractTrace(carrier)
	if err != nil {
		t.Fatal(err)
	}
	if extracted != parsed || carrier[TraceParentHeader] != parent {
		t.Fatalf("trace context changed: %#v", extracted)
	}
	for _, invalid := range []string{
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	} {
		if _, err := ParseTraceParent(invalid, ""); !errors.Is(err, ErrInvalidTraceContext) {
			t.Fatalf("invalid traceparent accepted: %s", invalid)
		}
	}
	if _, err := ParseTraceParent(parent, "vendor=ok\r\nforged=yes"); !errors.Is(err, ErrInvalidTraceContext) {
		t.Fatal("header injection in tracestate was accepted")
	}
}

func TestTraceContinuityAcrossRequiredBoundaries(t *testing.T) {
	sink := &MemoryTraceSink{Destination: "otlp://traces"}
	tracer, err := NewTracer(sink, RetentionSampler{NormalRate: 1}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	names := []string{SpanProjectCreate, SpanModelGenerate, SpanToolCall, SpanRepoCommit, SpanAuditCheck}
	var previousSpan string
	var traceID string
	for index, name := range names {
		child, span, err := tracer.Start(ctx, name, validCorrelation(), map[string]string{"aor.attempt": "1", "aor.project.id": "forged"})
		if err != nil {
			t.Fatal(err)
		}
		if err := span.End(child, SpanStatusOK, TraceOutcome{}, map[string]string{"aor.project.id": "forged-again"}); err != nil {
			t.Fatal(err)
		}
		record := sink.Spans[index]
		if index == 0 {
			traceID = record.TraceID
			if record.ParentSpanID != "" {
				t.Fatal("root span unexpectedly has a parent")
			}
		} else if record.ParentSpanID != previousSpan {
			t.Fatalf("span %s does not continue parent %s", name, previousSpan)
		}
		if record.TraceID != traceID {
			t.Fatal("trace ID changed across boundary")
		}
		if record.Attributes["aor.project.id"] != "project:1" {
			t.Fatal("caller overwrote mandatory project correlation")
		}
		previousSpan = record.SpanID
		ctx = child
	}
}

func TestRetentionSamplerNeverDropsCriticalOutcomes(t *testing.T) {
	trace := TraceContext{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7"}
	sampler := RetentionSampler{NormalRate: 0}
	if sampler.ShouldSample(trace, TraceOutcome{}) {
		t.Fatal("normal zero-rate trace was retained")
	}
	cases := []TraceOutcome{
		{Failed: true},
		{Failed: true, Attempt: 3},
		{Attempt: 3},
		{SecurityDenied: true},
		{BudgetDenied: true},
		{Critical: true},
	}
	for _, outcome := range cases {
		if !sampler.ShouldSample(trace, outcome) {
			t.Fatalf("critical outcome was dropped: %#v", outcome)
		}
	}
}

func TestTracerRetainsErrorAtZeroNormalRate(t *testing.T) {
	sink := &MemoryTraceSink{Destination: "otlp://traces"}
	tracer, err := NewTracer(sink, RetentionSampler{NormalRate: 0}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, span, err := tracer.Start(context.Background(), SpanAuditCheck, validCorrelation(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := span.End(ctx, SpanStatusError, TraceOutcome{Attempt: 3}, nil); err != nil {
		t.Fatal(err)
	}
	if len(sink.Spans) != 1 {
		t.Fatalf("error span count = %d", len(sink.Spans))
	}
}
