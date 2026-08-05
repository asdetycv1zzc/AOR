package projection

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/cloudevents"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestVerifyProjectConvergenceAfterWorkflowAndEventBusFaultRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store := eventing.NewMemoryStore()
	created := commitConvergenceProject(t, ctx, store, 1, contracts.ProjectCreated, "io.aor.project.created.v1")
	negotiating := commitConvergenceProject(t, ctx, store, 2, contracts.ProjectGoalNegotiating, "io.aor.goal.negotiation-started.v1")
	createdExternal := externalConvergenceEvent(t, created)
	negotiatingExternal := externalConvergenceEvent(t, negotiating)

	history := &fixedProjectLifecycleHistory{snapshot: aorworkflow.ProjectLifecycleSnapshot{
		TenantID: "tenant_1", ProjectID: "project_1", State: contracts.ProjectCreated, ProjectVersion: 1,
	}}
	replay := &fixedProjectEventReplay{tenantID: "tenant_1", events: []cloudevents.Event{createdExternal}}
	report, err := VerifyProjectConvergence(ctx, store, history, replay, "tenant_1", "project_1")
	if !errors.Is(err, ErrDurableConvergence) || report.Converged || report.PostgreSQLVersion != 2 || report.WorkflowVersion != 1 || report.EventBusVersion != 1 {
		t.Fatalf("faulted convergence report = %#v, error = %v", report, err)
	}
	if report.ReportSHA256 == "" || report.ProjectionReportSHA256 == "" {
		t.Fatalf("faulted report has no machine-verifiable digest: %#v", report)
	}

	history.snapshot = aorworkflow.ProjectLifecycleSnapshot{
		TenantID: "tenant_1", ProjectID: "project_1", State: contracts.ProjectGoalNegotiating,
		ProjectVersion: 2, ProcessedEvents: 1, RejectedSignals: 2,
	}
	replay.events = []cloudevents.Event{createdExternal, tamperConvergenceEvent(t, negotiatingExternal)}
	report, err = VerifyProjectConvergence(ctx, store, history, replay, "tenant_1", "project_1")
	if !errors.Is(err, ErrDurableConvergence) || report.PostgreSQLSHA256 != report.EventBusSHA256 || report.PostgreSQLProjectionSHA256 == report.EventBusProjectionSHA256 {
		t.Fatalf("non-lifecycle event bus drift report = %#v, error = %v", report, err)
	}

	replay.events = []cloudevents.Event{negotiatingExternal, createdExternal, createdExternal}
	report, err = VerifyProjectConvergence(ctx, store, history, replay, "tenant_1", "project_1")
	if err != nil || !report.Converged {
		t.Fatalf("recovered convergence report = %#v, error = %v", report, err)
	}
	if report.PostgreSQLSHA256 == "" || report.PostgreSQLSHA256 != report.WorkflowSHA256 || report.PostgreSQLSHA256 != report.EventBusSHA256 {
		t.Fatalf("recovered state digests = %#v", report)
	}
	if report.PostgreSQLProjectionSHA256 == "" || report.PostgreSQLProjectionSHA256 != report.EventBusProjectionSHA256 {
		t.Fatalf("recovered projection digests = %#v", report)
	}
	if report.EventBusReplayMessageCount != 3 || report.WorkflowRejectedSignals != 2 {
		t.Fatalf("fault recovery evidence = %#v", report)
	}
}

type fixedProjectLifecycleHistory struct {
	snapshot aorworkflow.ProjectLifecycleSnapshot
}

func (history *fixedProjectLifecycleHistory) Snapshot(context.Context, string, string) (aorworkflow.ProjectLifecycleSnapshot, error) {
	return history.snapshot, nil
}

type fixedProjectEventReplay struct {
	tenantID string
	events   []cloudevents.Event
}

func (replay *fixedProjectEventReplay) ReplayPending(ctx context.Context, handler func(context.Context, eventing.JetStreamDelivery) error) (uint64, error) {
	for index, event := range replay.events {
		if err := handler(ctx, eventing.JetStreamDelivery{Event: event, TenantID: replay.tenantID, Subject: "aor.events." + replay.tenantID + ".project"}); err != nil {
			return uint64(index), err
		}
	}
	return uint64(len(replay.events)), nil
}

func commitConvergenceProject(t *testing.T, ctx context.Context, store *eventing.MemoryStore, version int64, projectState contracts.ProjectState, eventType string) eventing.DomainEvent {
	t.Helper()
	project := state.Project{
		TenantID: "tenant_1", ID: "project_1", Name: "convergence", CreatedBy: "user_1",
		DataClassification: "INTERNAL", RiskTolerance: "MEDIUM", State: projectState,
		Version: version, GoalAgentCount: 1,
	}
	projectionState, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		TenantID         string          `json:"tenantId"`
		ProjectID        string          `json:"projectId"`
		AggregateVersion int64           `json:"aggregateVersion"`
		Projection       json.RawMessage `json:"projection"`
	}{TenantID: project.TenantID, ProjectID: project.ID, AggregateVersion: int64(version), Projection: projectionState})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := canonicaljson.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	resultDigest, err := canonicaljson.Digest(projectionState)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Execute(ctx, eventing.TransactionRequest{
		TenantID: "tenant_1", PrincipalID: "service_1", IdempotencyKey: eventType, RequestSHA256: resultDigest,
		Updates: []eventing.ProjectionUpdate{{
			TenantID: "tenant_1", ProjectID: "project_1", AggregateType: "project", AggregateID: "project_1",
			ExpectedVersion: int64(version - 1), NextVersion: int64(version), State: projectionState,
		}},
		Events: []eventing.DomainEvent{{
			EventID: "event_" + string(rune('0'+version)), TenantID: "tenant_1", ProjectID: "project_1",
			AggregateType: "project", AggregateID: "project_1", AggregateVersion: int64(version), Type: eventType,
			Payload: payload, PayloadSHA256: payloadDigest, OccurredAt: time.Date(2030, 1, int(version), 0, 0, 0, 0, time.UTC),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		}},
		Result: projectionState, ResultSHA256: resultDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Events[0]
}

func externalConvergenceEvent(t *testing.T, event eventing.DomainEvent) cloudevents.Event {
	t.Helper()
	external, err := eventing.Externalize(event, eventing.CloudEventOptions{Source: "urn:aor:service:orchestrator"})
	if err != nil {
		t.Fatal(err)
	}
	return external
}

func tamperConvergenceEvent(t *testing.T, event cloudevents.Event) cloudevents.Event {
	t.Helper()
	var payload struct {
		TenantID         string         `json:"tenantId"`
		ProjectID        string         `json:"projectId"`
		AggregateVersion int64          `json:"aggregateVersion"`
		Projection       map[string]any `json:"projection"`
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Projection["name"] = "tampered"
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event.Data = data
	return event
}
