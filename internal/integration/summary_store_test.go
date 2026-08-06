package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestEventSummaryStorePublishesCorrelatedExternalEvent(t *testing.T) {
	events := eventing.NewMemoryStore()
	clock := func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) }
	store, err := NewEventSummaryStore(events, clock)
	if err != nil {
		t.Fatal(err)
	}
	summary := PlanSupervisorSummary{
		SummaryVersion: 1, TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1",
		State: SummaryMergePending, OwnerTaskID: "task-1", BaseCommit: strings.Repeat("a", 40),
		Modules:    []ModuleOutcome{{TaskID: "task-1", ModuleID: "module-1", State: contracts.TaskPassed, Version: 2}},
		Deviations: []string{}, Risks: []string{}, EvidenceSHA256: []string{}, CreatedAt: clock(),
	}
	summary.SummarySHA256, err = summaryDigest(summary)
	if err != nil {
		t.Fatal(err)
	}
	trace := observability.TraceContext{
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef", TraceFlags: 1, TraceState: "aor=test",
	}
	ctx, err := observability.ContextWithTrace(context.Background(), trace)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(ctx, summary); err != nil {
		t.Fatal(err)
	}

	stored, err := events.ListEvents(context.Background(), summary.TenantID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored events = %#v, %v", stored, err)
	}
	external, err := eventing.Externalize(stored[0], eventing.CloudEventOptions{Source: "urn:aor:test:integration"})
	if err != nil {
		t.Fatal(err)
	}
	traceparent, err := trace.TraceParent()
	if err != nil {
		t.Fatal(err)
	}
	if external.Type != "io.aor.integration.summary-published.v1" || external.Subject != "projects/project-1" {
		t.Fatalf("external event identity = %#v", external)
	}
	if external.Traceparent != traceparent || external.Tracestate != trace.TraceState || external.ProjectID != summary.ProjectID {
		t.Fatalf("event trace and project correlation = %#v", external)
	}
	if external.TaskID != summary.OwnerTaskID || external.TaskIDReason != "" || external.AgentRunReason != "NOT_APPLICABLE" {
		t.Fatalf("event scoped correlation = %#v", external)
	}
}
