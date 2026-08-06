package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	SpanProjectCreate    = "aor.project.create"
	SpanGoalTurn         = "aor.goal.turn"
	SpanPlanGenerate     = "aor.plan.generate"
	SpanAgentLease       = "aor.agent.lease"
	SpanModelGenerate    = "aor.model.generate"
	SpanToolCall         = "aor.tool.call"
	SpanSandboxExec      = "aor.sandbox.exec"
	SpanRepoCommit       = "aor.repo.commit"
	SpanAuditCheck       = "aor.audit.check"
	SpanAuditLLM         = "aor.audit.llm"
	SpanIntegrationMerge = "aor.integration.merge"
	SpanKnowledgeSearch  = "aor.knowledge.search"
	SpanKnowledgeRead    = "aor.knowledge.read"
	SpanApprovalCommit   = "aor.approval.commit"
)

type SpanStatus string

const (
	SpanStatusUnset SpanStatus = "UNSET"
	SpanStatusOK    SpanStatus = "OK"
	SpanStatusError SpanStatus = "ERROR"
)

type SpanRecord struct {
	TraceID      string            `json:"trace_id"`
	SpanID       string            `json:"span_id"`
	ParentSpanID string            `json:"parent_span_id"`
	TraceState   string            `json:"tracestate,omitempty"`
	Name         string            `json:"name"`
	StartedAt    time.Time         `json:"started_at"`
	EndedAt      time.Time         `json:"ended_at"`
	Status       SpanStatus        `json:"status"`
	Attributes   map[string]string `json:"attributes"`
}

type TraceSink interface {
	TraceDestination() string
	WriteSpan(context.Context, SpanRecord) error
}

type Tracer struct {
	sink    TraceSink
	sampler Sampler
	limits  Limits
	clock   func() time.Time
	backend oteltrace.Tracer
}

func NewTracer(sink TraceSink, sampler Sampler, limits Limits) (*Tracer, error) {
	if sink == nil || sink.TraceDestination() == "" || sampler == nil {
		return nil, ErrInvalidAttribute
	}
	return &Tracer{sink: sink, sampler: sampler, limits: limits.normalized(), clock: time.Now}, nil
}

func (t *Tracer) SetClockForTest(clock func() time.Time) {
	if clock != nil {
		t.clock = clock
	}
}

type Span struct {
	tracer      *Tracer
	record      SpanRecord
	correlation Correlation
	backend     oteltrace.Span
	mu          sync.Mutex
	ended       bool
}

func (t *Tracer) Start(ctx context.Context, name string, correlation Correlation, attributes map[string]string) (context.Context, *Span, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validSpanName(name) {
		return nil, nil, ErrInvalidAttribute
	}
	if err := correlation.Validate(); err != nil {
		return nil, nil, err
	}
	parent, hasParent := TraceFromContext(ctx)
	if hasParent {
		if err := parent.Validate(); err != nil {
			return nil, nil, err
		}
	} else if t.backend == nil {
		var err error
		parent, err = NewRootTraceContext(false)
		if err != nil {
			return nil, nil, err
		}
	}
	combined := cloneStrings(attributes)
	for key, value := range correlation.traceAttributes() {
		combined[key] = value
	}
	parentSpanID := ""
	if hasParent {
		parentSpanID = parent.SpanID
	}
	if t.backend != nil {
		startedAt := t.clock().UTC()
		backendContext := ctx
		if hasParent {
			spanContext, err := openTelemetrySpanContext(parent)
			if err != nil {
				return nil, nil, err
			}
			backendContext = oteltrace.ContextWithRemoteSpanContext(backendContext, spanContext)
		}
		backendContext, backendSpan := t.backend.Start(backendContext, name, oteltrace.WithTimestamp(startedAt))
		spanContext := backendSpan.SpanContext()
		record := SpanRecord{
			TraceID: spanContext.TraceID().String(), SpanID: spanContext.SpanID().String(), ParentSpanID: parentSpanID,
			TraceState: spanContext.TraceState().String(), Name: name, StartedAt: startedAt, Attributes: combined,
		}
		propagation := TraceContext{TraceID: record.TraceID, SpanID: record.SpanID, TraceFlags: byte(spanContext.TraceFlags()), TraceState: record.TraceState}
		childContext, err := ContextWithTrace(backendContext, propagation)
		if err != nil {
			backendSpan.End(oteltrace.WithTimestamp(t.clock().UTC()))
			return nil, nil, err
		}
		childContext = context.WithValue(childContext, tracerContextKey{}, t)
		return childContext, &Span{tracer: t, record: record, correlation: correlation, backend: backendSpan}, nil
	}
	spanID, err := randomHex(8)
	if err != nil {
		return nil, nil, err
	}
	record := SpanRecord{
		TraceID: parent.TraceID, SpanID: spanID, ParentSpanID: parentSpanID,
		TraceState: parent.TraceState, Name: name, StartedAt: t.clock().UTC(), Attributes: combined,
	}
	propagation := TraceContext{TraceID: record.TraceID, SpanID: record.SpanID, TraceFlags: parent.TraceFlags, TraceState: record.TraceState}
	childContext, err := ContextWithTrace(ctx, propagation)
	if err != nil {
		return nil, nil, err
	}
	return childContext, &Span{tracer: t, record: record, correlation: correlation}, nil
}

func (s *Span) End(ctx context.Context, status SpanStatus, outcome TraceOutcome, attributes map[string]string) error {
	if status != SpanStatusUnset && status != SpanStatusOK && status != SpanStatusError {
		return ErrInvalidAttribute
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return ErrSpanEnded
	}
	if status == SpanStatusError {
		outcome.Failed = true
	}
	s.record.EndedAt = s.tracer.clock().UTC()
	s.record.Status = status
	for key, value := range attributes {
		s.record.Attributes[key] = value
	}
	for key, value := range s.correlation.traceAttributes() {
		s.record.Attributes[key] = value
	}
	if outcome.Attempt > 0 {
		s.record.Attributes["aor.attempt"] = strconv.Itoa(outcome.Attempt)
	}
	if outcome.SecurityDenied {
		s.record.Attributes["aor.security.denied"] = "true"
	}
	if outcome.BudgetDenied {
		s.record.Attributes["aor.budget.denied"] = "true"
	}
	if outcome.Critical {
		s.record.Attributes["aor.severity"] = "CRITICAL"
	}
	safe, _, err := sanitizeAttributes(s.record.Attributes, s.tracer.limits)
	if err != nil {
		return err
	}
	s.record.Attributes = safe
	if err := boundSpanAttributes(&s.record, s.tracer.limits.MaxEventBytes); err != nil {
		return err
	}
	s.ended = true
	if s.backend != nil {
		keys := make([]string, 0, len(s.record.Attributes))
		for key := range s.record.Attributes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		values := make([]attribute.KeyValue, 0, len(keys))
		for _, key := range keys {
			value := s.record.Attributes[key]
			if key == "aor.attempt" {
				if attempt, err := strconv.ParseInt(value, 10, 64); err == nil {
					values = append(values, attribute.Int64(key, attempt))
					continue
				}
			}
			values = append(values, attribute.String(key, value))
		}
		s.backend.SetAttributes(values...)
		switch status {
		case SpanStatusOK:
			s.backend.SetStatus(codes.Ok, "")
		case SpanStatusError:
			s.backend.SetStatus(codes.Error, "operation failed")
		}
		s.backend.End(oteltrace.WithTimestamp(s.record.EndedAt))
		return nil
	}
	trace := TraceContext{TraceID: s.record.TraceID, SpanID: s.record.SpanID}
	if !s.tracer.sampler.ShouldSample(trace, outcome) {
		return nil
	}
	return s.tracer.sink.WriteSpan(ctx, s.record)
}

func boundSpanAttributes(record *SpanRecord, maximum int) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(payload) <= maximum {
		return nil
	}
	keys := make([]string, 0, len(record.Attributes))
	for key := range record.Attributes {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys {
		delete(record.Attributes, key)
		payload, err = json.Marshal(record)
		if err != nil {
			return err
		}
		if len(payload) <= maximum {
			return nil
		}
	}
	return ErrEventTooLarge
}

func validSpanName(name string) bool {
	switch name {
	case SpanProjectCreate, SpanGoalTurn, SpanPlanGenerate, SpanAgentLease, SpanModelGenerate,
		SpanToolCall, SpanSandboxExec, SpanRepoCommit, SpanAuditCheck, SpanAuditLLM,
		SpanIntegrationMerge, SpanKnowledgeSearch, SpanKnowledgeRead, SpanApprovalCommit:
		return true
	default:
		return false
	}
}

type MemoryTraceSink struct {
	Destination string
	mu          sync.Mutex
	Spans       []SpanRecord
}

func (s *MemoryTraceSink) TraceDestination() string {
	return s.Destination
}

func (s *MemoryTraceSink) WriteSpan(_ context.Context, record SpanRecord) error {
	if record.EndedAt.Before(record.StartedAt) {
		return fmt.Errorf("%w: span ends before it starts", ErrInvalidAttribute)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copyRecord := record
	copyRecord.Attributes = cloneStrings(record.Attributes)
	s.Spans = append(s.Spans, copyRecord)
	return nil
}

func cloneStrings(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
