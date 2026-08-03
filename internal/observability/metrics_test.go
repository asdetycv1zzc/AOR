package observability

import (
	"context"
	"errors"
	"testing"
)

func TestDefaultMetricsCoverRequiredSignals(t *testing.T) {
	required := []string{
		"aor_active_agents", "aor_agent_queue_depth", "aor_agent_lease_expired_total",
		"aor_model_requests_total", "aor_model_tokens_total", "aor_model_cost_minor_total",
		"aor_budget_remaining_minor", "aor_tool_invocations_total", "aor_sandbox_duration_seconds",
		"aor_audit_runs_total", "aor_audit_attempts_per_module", "aor_findings_total",
		"aor_modules_blocked_total", "aor_workflow_replay_failures_total", "aor_event_outbox_lag_seconds",
		"aor_knowledge_reads_total", "aor_api_request_duration_seconds", "aor_module_rework_total",
		"aor_user_takeovers_total", "aor_cache_requests_total",
	}
	seen := map[string]bool{}
	for _, descriptor := range DefaultMetricDescriptors() {
		seen[descriptor.Name] = true
	}
	for _, name := range required {
		if !seen[name] {
			t.Fatalf("required metric missing: %s", name)
		}
	}
}

func TestMetricRegistryRejectsRawHighCardinalityLabels(t *testing.T) {
	_, err := NewMetricRegistry([]MetricDescriptor{{
		Name: "bad_metric", Kind: MetricCounter, Labels: []string{"task_id"},
		CardinalityLimits: map[string]int{"task_id": 10}, SeriesLimit: 10,
	}}, &MemoryMetricSink{})
	if !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("raw task ID label accepted: %v", err)
	}
}

func TestMetricRegistryBoundsValuesAndSeries(t *testing.T) {
	sink := &MemoryMetricSink{}
	registry, err := NewMetricRegistry([]MetricDescriptor{{
		Name: "bounded_metric", Kind: MetricCounter, Labels: []string{"project"},
		CardinalityLimits: map[string]int{"project": 2}, SeriesLimit: 2,
	}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"one", "two", "three"} {
		if err := registry.Record(context.Background(), "bounded_metric", 1, map[string]string{"project": project}); err != nil {
			t.Fatal(err)
		}
	}
	if got := sink.Points[2].Labels["project"]; got != "__overflow__" {
		t.Fatalf("overflow label = %q", got)
	}
	if err := registry.Record(context.Background(), "bounded_metric", 1, map[string]string{"project": "one", "task": "x"}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatal("unexpected label was accepted")
	}
	if err := registry.Record(context.Background(), "bounded_metric", 1, map[string]string{"project": "api_" + "key=abcdefghijk"}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatal("credential-like metric label was accepted")
	}
}

func TestMetricRegistryCopiesDescriptorPolicy(t *testing.T) {
	descriptor := MetricDescriptor{
		Name: "stable_metric", Kind: MetricGauge, Labels: []string{"role"},
		CardinalityLimits: map[string]int{"role": 2}, SeriesLimit: 2,
	}
	registry, err := NewMetricRegistry([]MetricDescriptor{descriptor}, &MemoryMetricSink{})
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Labels[0] = "task_id"
	descriptor.CardinalityLimits["role"] = 1000000
	if err := registry.Record(context.Background(), "stable_metric", 1, map[string]string{"role": "executor"}); err != nil {
		t.Fatalf("caller mutation changed registered descriptor: %v", err)
	}
}
