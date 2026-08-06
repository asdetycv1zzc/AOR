package observability

import (
	"context"
	"encoding/hex"
	"net/url"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const instrumentationScope = "github.com/akimisaka/aor/internal/observability"

type tracerContextKey struct{}

var processTracer atomic.Pointer[Tracer]

func NewOTLPTracer(ctx context.Context, component, endpoint string) (*Tracer, func(context.Context) error, error) {
	if ctx == nil || component == "" || !validOTLPEndpoint(endpoint) {
		return nil, nil, ErrInvalidAttribute
	}
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(endpoint),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
		otlptracehttp.WithTimeout(5*time.Second),
	)
	if err != nil {
		return nil, nil, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", component))),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithMaxQueueSize(2048),
			sdktrace.WithMaxExportBatchSize(256),
			sdktrace.WithBatchTimeout(2*time.Second),
			sdktrace.WithExportTimeout(5*time.Second),
		),
	)
	tracer := &Tracer{sampler: RetentionSampler{NormalRate: 1}, limits: DefaultLimits(), clock: time.Now, backend: provider.Tracer(instrumentationScope)}
	return tracer, provider.Shutdown, nil
}

func ContextWithTracer(ctx context.Context, tracer *Tracer) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if tracer == nil {
		return ctx
	}
	return context.WithValue(ctx, tracerContextKey{}, tracer)
}

func TracerFromContext(ctx context.Context) (*Tracer, bool) {
	if ctx != nil {
		if tracer, ok := ctx.Value(tracerContextKey{}).(*Tracer); ok && tracer != nil {
			return tracer, true
		}
	}
	tracer := processTracer.Load()
	return tracer, tracer != nil
}

func SetDefaultTracer(tracer *Tracer) func() {
	previous := processTracer.Swap(tracer)
	return func() {
		processTracer.CompareAndSwap(tracer, previous)
	}
}

func StartSpan(ctx context.Context, name string, correlation Correlation, attributes map[string]string) (context.Context, *Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	tracer, found := TracerFromContext(ctx)
	if !found {
		return ctx, nil
	}
	child, span, err := tracer.Start(ContextWithTracer(ctx, tracer), name, correlation, attributes)
	if err != nil {
		return ctx, nil
	}
	return child, span
}

func EndSpan(ctx context.Context, span *Span, operationErr error, outcome TraceOutcome, attributes map[string]string) {
	if span == nil {
		return
	}
	status := SpanStatusOK
	if operationErr != nil {
		status = SpanStatusError
		outcome.Failed = true
	}
	_ = span.End(ctx, status, outcome, attributes)
}

func openTelemetrySpanContext(value TraceContext) (oteltrace.SpanContext, error) {
	traceBytes, traceErr := hex.DecodeString(value.TraceID)
	spanBytes, spanErr := hex.DecodeString(value.SpanID)
	traceState, stateErr := oteltrace.ParseTraceState(value.TraceState)
	if traceErr != nil || spanErr != nil || stateErr != nil || len(traceBytes) != 16 || len(spanBytes) != 8 {
		return oteltrace.SpanContext{}, ErrInvalidTraceContext
	}
	var traceID oteltrace.TraceID
	var spanID oteltrace.SpanID
	copy(traceID[:], traceBytes)
	copy(spanID[:], spanBytes)
	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: oteltrace.TraceFlags(value.TraceFlags), TraceState: traceState, Remote: true,
	})
	if !spanContext.IsValid() {
		return oteltrace.SpanContext{}, ErrInvalidTraceContext
	}
	return spanContext, nil
}

func validOTLPEndpoint(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && (parsed.Path == "" || parsed.Path == "/")
}
