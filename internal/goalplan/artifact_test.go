package goalplan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/google/uuid"
)

func TestEventArtifactStoreIsImmutableScopedAndIdempotent(t *testing.T) {
	events := eventing.NewMemoryStore()
	store, err := NewEventArtifactStore(events, goalPlanClock)
	if err != nil {
		t.Fatal(err)
	}
	artifact := SpecArtifact{TenantID: "tenant_1", ProjectID: "prj_1", Kind: ArtifactGoalDraft, SpecID: "goal_1", Version: 1, Content: []byte(`{"value":1}`), CreatedBy: "agt_goal"}
	trace := observability.TraceContext{
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef", TraceFlags: 1, TraceState: "aor=test",
	}
	ctx, err := observability.ContextWithTrace(context.Background(), trace)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Put(ctx, artifact)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Content = []byte("{ \"value\" : 1 }")
	second, err := store.Put(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if first.ArtifactSHA256 != second.ArtifactSHA256 || first.URI != second.URI {
		t.Fatalf("canonical identity changed: %#v %#v", first, second)
	}
	loaded, found, err := store.Get(context.Background(), "tenant_1", "prj_1", ArtifactGoalDraft, "goal_1", 1)
	if err != nil || !found {
		t.Fatalf("load = found %v err %v", found, err)
	}
	loaded.Content[0] = 'x'
	reloaded, _, err := store.Get(context.Background(), "tenant_1", "prj_1", ArtifactGoalDraft, "goal_1", 1)
	if err != nil || reloaded.Content[0] == 'x' {
		t.Fatalf("stored content mutated: %q err %v", reloaded.Content, err)
	}
	if _, found, err := store.Get(context.Background(), "tenant_1", "prj_2", ArtifactGoalDraft, "goal_1", 1); err != nil || found {
		t.Fatalf("cross-project lookup = found %v err %v", found, err)
	}
	if stats := events.Stats(); stats.Events != 1 || stats.Projections != 1 {
		t.Fatalf("event stats = %#v", stats)
	}
	snapshot, err := events.LoadReconciliationSnapshot(context.Background(), "tenant_1")
	if err != nil || len(snapshot.Events) != 1 {
		t.Fatalf("event snapshot = %#v, %v", snapshot, err)
	}
	eventID, err := uuid.Parse(snapshot.Events[0].EventID)
	if err != nil || eventID.Version() != uuid.Version(7) {
		t.Fatalf("event ID = %q, %v", snapshot.Events[0].EventID, err)
	}
	external, err := eventing.Externalize(snapshot.Events[0], eventing.CloudEventOptions{Source: "urn:aor:test:goal-plan"})
	if err != nil {
		t.Fatal(err)
	}
	traceparent, err := trace.TraceParent()
	if err != nil {
		t.Fatal(err)
	}
	if external.Traceparent != traceparent || external.Tracestate != trace.TraceState || external.ProjectID != artifact.ProjectID {
		t.Fatalf("event trace and project correlation = %#v", external)
	}
	if external.TaskIDReason != "NOT_CREATED" || external.AgentRunReason != "NOT_CREATED" {
		t.Fatalf("event scoped correlation = %#v", external)
	}
}

func TestEventArtifactStoreRejectsImmutableConflict(t *testing.T) {
	events := eventing.NewMemoryStore()
	store, _ := NewEventArtifactStore(events, goalPlanClock)
	artifact := SpecArtifact{TenantID: "tenant_1", ProjectID: "prj_1", Kind: ArtifactPlanSpec, SpecID: "plan_1", Version: 1, Content: []byte(`{"value":1}`), CreatedBy: "agt_plan"}
	if _, err := store.Put(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	artifact.Content = []byte(`{"value":2}`)
	if _, err := store.Put(context.Background(), artifact); !errors.Is(err, ErrArtifactConflict) {
		t.Fatalf("conflict = %v", err)
	}
}

func TestEventArtifactStoreRecoversUnknownCommitResult(t *testing.T) {
	events := eventing.NewMemoryStore()
	store, _ := NewEventArtifactStore(events, goalPlanClock)
	artifact := SpecArtifact{TenantID: "tenant_1", ProjectID: "prj_1", Kind: ArtifactUserMessage, SpecID: "msg_1", Version: 1, Content: []byte("user input"), CreatedBy: "usr_1"}
	events.FailNext(eventing.FailureAfterCommit)
	if _, err := store.Put(context.Background(), artifact); !errors.Is(err, eventing.ErrCommitResultUnknown) {
		t.Fatalf("unknown commit = %v", err)
	}
	if _, err := store.Put(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
}

func goalPlanClock() time.Time {
	return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
}
