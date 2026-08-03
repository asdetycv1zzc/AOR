package observability

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type MetricKind string

const (
	MetricCounter   MetricKind = "COUNTER"
	MetricGauge     MetricKind = "GAUGE"
	MetricHistogram MetricKind = "HISTOGRAM"
)

type MetricDescriptor struct {
	Name              string
	Kind              MetricKind
	Labels            []string
	CardinalityLimits map[string]int
	SeriesLimit       int
}

type MetricPoint struct {
	Name      string            `json:"name"`
	Kind      MetricKind        `json:"kind"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
}

type MetricSink interface {
	WriteMetric(context.Context, MetricPoint) error
}

type MetricRegistry struct {
	descriptors map[string]MetricDescriptor
	sink        MetricSink
	limiter     *cardinalityLimiter
	clock       func() time.Time
}

func NewMetricRegistry(descriptors []MetricDescriptor, sink MetricSink) (*MetricRegistry, error) {
	if sink == nil {
		return nil, ErrInvalidMetric
	}
	registry := &MetricRegistry{
		descriptors: map[string]MetricDescriptor{}, sink: sink,
		limiter: newCardinalityLimiter(), clock: time.Now,
	}
	for _, descriptor := range descriptors {
		if err := validateDescriptor(descriptor); err != nil {
			return nil, err
		}
		if _, exists := registry.descriptors[descriptor.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate descriptor %s", ErrInvalidMetric, descriptor.Name)
		}
		registry.descriptors[descriptor.Name] = cloneMetricDescriptor(descriptor)
	}
	return registry, nil
}

func NewDefaultMetricRegistry(sink MetricSink) (*MetricRegistry, error) {
	return NewMetricRegistry(DefaultMetricDescriptors(), sink)
}

func (r *MetricRegistry) SetClockForTest(clock func() time.Time) {
	if clock != nil {
		r.clock = clock
	}
}

func (r *MetricRegistry) Record(ctx context.Context, name string, value float64, labels map[string]string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	descriptor, exists := r.descriptors[name]
	if !exists || math.IsNaN(value) || math.IsInf(value, 0) || (descriptor.Kind == MetricCounter && value < 0) {
		return ErrInvalidMetric
	}
	if len(labels) != len(descriptor.Labels) {
		return ErrInvalidMetric
	}
	normalized := make(map[string]string, len(labels))
	for _, label := range descriptor.Labels {
		value, exists := labels[label]
		if !exists || !safeMetricLabelValue(value) {
			return ErrInvalidMetric
		}
		limit := descriptor.CardinalityLimits[label]
		normalized[label] = r.limiter.value(name, label, value, limit)
	}
	if !r.limiter.series(name, normalized, descriptor.SeriesLimit) {
		for key := range normalized {
			normalized[key] = "__overflow__"
		}
	}
	return r.sink.WriteMetric(ctx, MetricPoint{Name: name, Kind: descriptor.Kind, Value: value, Labels: normalized, Timestamp: r.clock().UTC()})
}

func cloneMetricDescriptor(descriptor MetricDescriptor) MetricDescriptor {
	copyDescriptor := descriptor
	copyDescriptor.Labels = append([]string(nil), descriptor.Labels...)
	copyDescriptor.CardinalityLimits = make(map[string]int, len(descriptor.CardinalityLimits))
	for label, limit := range descriptor.CardinalityLimits {
		copyDescriptor.CardinalityLimits[label] = limit
	}
	return copyDescriptor
}

func safeMetricLabelValue(value string) bool {
	if value == "" || value == "__overflow__" || len(value) > 128 {
		return false
	}
	if _, changed := redactValue(value); changed {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func validateDescriptor(descriptor MetricDescriptor) error {
	if !attributeKeyPattern.MatchString(descriptor.Name) || descriptor.SeriesLimit <= 0 {
		return ErrInvalidMetric
	}
	switch descriptor.Kind {
	case MetricCounter, MetricGauge, MetricHistogram:
	default:
		return ErrInvalidMetric
	}
	seen := map[string]struct{}{}
	for _, label := range descriptor.Labels {
		if !attributeKeyPattern.MatchString(label) || forbiddenMetricLabel(label) || descriptor.CardinalityLimits[label] <= 0 {
			return ErrInvalidMetric
		}
		if _, exists := seen[label]; exists {
			return ErrInvalidMetric
		}
		seen[label] = struct{}{}
	}
	if len(descriptor.CardinalityLimits) != len(descriptor.Labels) {
		return ErrInvalidMetric
	}
	return nil
}

func forbiddenMetricLabel(label string) bool {
	label = strings.ToLower(label)
	switch label {
	case "project_id", "task_id", "workflow_id", "agent_run_id", "trace_id", "span_id", "principal_id", "artifact_id", "approval_id", "request_id", "session_id":
		return true
	default:
		return strings.HasSuffix(label, "_sha256") || strings.HasSuffix(label, "_digest")
	}
}

func DefaultMetricDescriptors() []MetricDescriptor {
	return []MetricDescriptor{
		descriptor("aor_active_agents", MetricGauge, 1000, limits("role", 32, "project", 100)),
		descriptor("aor_agent_queue_depth", MetricGauge, 256, limits("role", 32, "priority", 8)),
		descriptor("aor_agent_lease_expired_total", MetricCounter, 64, limits("role", 32)),
		descriptor("aor_agent_concurrency_limit", MetricGauge, 64, limits("role", 32)),
		descriptor("aor_agent_dispatch_duration_seconds", MetricHistogram, 256, limits("role", 32)),
		descriptor("aor_model_requests_total", MetricCounter, 2000, limits("provider", 32, "model", 100, "status", 16)),
		descriptor("aor_model_tokens_total", MetricCounter, 1000, limits("provider", 32, "model", 100, "direction", 4)),
		descriptor("aor_model_cost_minor_total", MetricCounter, 10000, limits("provider", 32, "model", 100, "project", 100)),
		descriptor("aor_budget_remaining_minor", MetricGauge, 256, limits("scope", 128)),
		descriptor("aor_tool_invocations_total", MetricCounter, 10000, limits("tool", 200, "risk", 8, "decision", 16, "status", 16)),
		descriptor("aor_sandbox_duration_seconds", MetricHistogram, 128, limits("level", 4, "role", 32)),
		descriptor("aor_audit_runs_total", MetricCounter, 256, limits("phase", 16, "verdict", 8)),
		descriptor("aor_audit_attempts_per_module", MetricHistogram, 1, map[string]int{}),
		descriptor("aor_findings_total", MetricCounter, 512, limits("severity", 8, "category", 64)),
		descriptor("aor_modules_blocked_total", MetricCounter, 128, limits("reason", 64)),
		descriptor("aor_workflow_replay_failures_total", MetricCounter, 1, map[string]int{}),
		descriptor("aor_event_outbox_lag_seconds", MetricGauge, 1, map[string]int{}),
		descriptor("aor_state_projection_staleness_seconds", MetricGauge, 1, map[string]int{}),
		descriptor("aor_knowledge_reads_total", MetricCounter, 16, limits("trust_level", 8)),
		descriptor("aor_api_request_duration_seconds", MetricHistogram, 5000, limits("route", 128, "status", 32)),
		descriptor("aor_module_rework_total", MetricCounter, 128, limits("reason", 64)),
		descriptor("aor_user_takeovers_total", MetricCounter, 64, limits("reason", 32)),
		descriptor("aor_cache_requests_total", MetricCounter, 512, limits("model", 100, "result", 4)),
		descriptor("aor_security_events_total", MetricCounter, 256, limits("event", 64, "severity", 8)),
		descriptor("aor_workflow_stuck", MetricGauge, 64, limits("workflow_type", 32)),
		descriptor("aor_backup_runs_total", MetricCounter, 16, limits("status", 8)),
		descriptor("aor_sandbox_operations_total", MetricCounter, 128, limits("operation", 8, "status", 16, "level", 4)),
	}
}

func descriptor(name string, kind MetricKind, seriesLimit int, cardinality map[string]int) MetricDescriptor {
	labels := make([]string, 0, len(cardinality))
	for label := range cardinality {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return MetricDescriptor{Name: name, Kind: kind, Labels: labels, CardinalityLimits: cardinality, SeriesLimit: seriesLimit}
}

func limits(values ...any) map[string]int {
	result := make(map[string]int, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		result[values[index].(string)] = values[index+1].(int)
	}
	return result
}

type cardinalityLimiter struct {
	mu           sync.Mutex
	values       map[string]map[string]struct{}
	seriesValues map[string]map[string]struct{}
}

func newCardinalityLimiter() *cardinalityLimiter {
	return &cardinalityLimiter{values: map[string]map[string]struct{}{}, seriesValues: map[string]map[string]struct{}{}}
}

func (l *cardinalityLimiter) value(metric, label, value string, limit int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := metric + "\x00" + label
	seen := l.values[key]
	if seen == nil {
		seen = map[string]struct{}{}
		l.values[key] = seen
	}
	if _, exists := seen[value]; exists {
		return value
	}
	if len(seen) >= limit {
		return "__overflow__"
	}
	seen[value] = struct{}{}
	return value
}

func (l *cardinalityLimiter) series(metric string, labels map[string]string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(labels[key])
		builder.WriteByte(0)
	}
	seen := l.seriesValues[metric]
	if seen == nil {
		seen = map[string]struct{}{}
		l.seriesValues[metric] = seen
	}
	key := builder.String()
	if _, exists := seen[key]; exists {
		return true
	}
	if len(seen) >= limit {
		return false
	}
	seen[key] = struct{}{}
	return true
}

type MemoryMetricSink struct {
	mu     sync.Mutex
	Points []MetricPoint
}

func (s *MemoryMetricSink) WriteMetric(_ context.Context, point MetricPoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyPoint := point
	copyPoint.Labels = cloneStrings(point.Labels)
	s.Points = append(s.Points, copyPoint)
	return nil
}
