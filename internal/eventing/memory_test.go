package eventing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestMemoryStoreDeduplicatesOneHundredIdenticalCommands(t *testing.T) {
	store := NewMemoryStore()
	request := transactionRequest("request-a")
	for attempt := 0; attempt < 100; attempt++ {
		result, err := store.Execute(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if result.Duplicate != (attempt > 0) {
			t.Fatalf("attempt %d duplicate = %v", attempt, result.Duplicate)
		}
	}
	stats := store.Stats()
	if stats.Events != 1 || stats.Outbox != 1 || stats.CommandResults != 1 || stats.Projections != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestMemoryStoreBindsReplayStateIntoAtomicSnapshot(t *testing.T) {
	store := NewMemoryStore()
	request := transactionRequest("replay-state")
	result, err := store.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := canonicaljson.Digest(request.Updates[0].State)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || string(result.Events[0].ReplayState) != string(request.Updates[0].State) || result.Events[0].ReplayStateSHA256 != expectedDigest {
		t.Fatalf("bound replay event = %#v", result.Events)
	}
	events, err := store.ListEvents(context.Background(), request.TenantID)
	if err != nil || len(events) != 1 || len(events[0].ReplayState) != 0 || events[0].ReplayStateSHA256 != "" {
		t.Fatalf("ordinary event log exposed replay state: %#v error=%v", events, err)
	}
	snapshot, err := store.LoadReconciliationSnapshot(context.Background(), request.TenantID)
	if err != nil || len(snapshot.Events) != 1 || len(snapshot.Projections) != 1 {
		t.Fatalf("snapshot = %#v error=%v", snapshot, err)
	}
	snapshot.Events[0].ReplayState[0] = '['
	again, err := store.LoadReconciliationSnapshot(context.Background(), request.TenantID)
	if err != nil || string(again.Events[0].ReplayState) != string(request.Updates[0].State) {
		t.Fatalf("snapshot mutation escaped = %#v error=%v", again, err)
	}
}

func TestMemoryStoreRejectsIdempotencyKeyWithDifferentBody(t *testing.T) {
	store := NewMemoryStore()
	request := transactionRequest("request-a")
	if _, err := store.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	conflict := request
	conflict.RequestSHA256 = digestOne()
	_, err := store.Execute(context.Background(), conflict)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("conflict = %#v", err)
	}
	if store.Stats().Events != 1 {
		t.Fatal("conflicting duplicate mutated event history")
	}
}

func TestMemoryStoreCrashWindowsAreAtomicAndRecoverable(t *testing.T) {
	store := NewMemoryStore()
	request := transactionRequest("request-a")
	store.FailNext(FailureBeforeCommit)
	if _, err := store.Execute(context.Background(), request); !errors.Is(err, ErrInjectedFailure) {
		t.Fatalf("before commit error = %v", err)
	}
	if stats := store.Stats(); stats.Events != 0 || stats.Projections != 0 || stats.Outbox != 0 {
		t.Fatalf("partial pre-commit state = %#v", stats)
	}

	store.FailNext(FailureAfterCommit)
	if _, err := store.Execute(context.Background(), request); !errors.Is(err, ErrCommitResultUnknown) {
		t.Fatalf("after commit error = %v", err)
	}
	if stats := store.Stats(); stats.Events != 1 || stats.Projections != 1 || stats.Outbox != 1 {
		t.Fatalf("committed state missing = %#v", stats)
	}
	result, err := store.Execute(context.Background(), request)
	if err != nil || !result.Duplicate {
		t.Fatalf("reconciliation retry = %#v, %v", result, err)
	}
}

func TestMemoryStoreScopesProjectionAndIdempotencyByTenant(t *testing.T) {
	store := NewMemoryStore()
	first := transactionRequest("request-a")
	if _, err := store.Execute(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := transactionRequest("request-b")
	second.TenantID = "tenant_2"
	second.Updates[0].TenantID = "tenant_2"
	second.Events[0].TenantID = "tenant_2"
	second.Events[0].EventID = "evt_2"
	if _, err := store.Execute(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if stats := store.Stats(); stats.Projections != 2 || stats.CommandResults != 2 {
		t.Fatalf("tenant scoped stats = %#v", stats)
	}
}

func TestMemoryStoreListsProjectProjectionsInStableOrder(t *testing.T) {
	store := NewMemoryStore()
	for _, input := range []struct {
		tenantID, projectID, aggregateID string
	}{
		{tenantID: "tenant_1", projectID: "prj_1", aggregateID: "task_b"},
		{tenantID: "tenant_1", projectID: "prj_1", aggregateID: "task_a"},
		{tenantID: "tenant_1", projectID: "prj_2", aggregateID: "task_hidden_project"},
		{tenantID: "tenant_2", projectID: "prj_1", aggregateID: "task_hidden_tenant"},
	} {
		request := projectionTransaction(input.tenantID, input.projectID, "task", input.aggregateID)
		if _, err := store.Execute(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	projections, err := store.ListProjections(context.Background(), "tenant_1", "prj_1", "task")
	if err != nil {
		t.Fatal(err)
	}
	if len(projections) != 2 || projections[0].AggregateID != "task_a" || projections[1].AggregateID != "task_b" {
		t.Fatalf("projections = %#v", projections)
	}
}

func TestMemoryStoreRejectsMismatchedContentDigests(t *testing.T) {
	store := NewMemoryStore()
	request := transactionRequest("request-a")
	request.Events[0].PayloadSHA256 = digestZero()
	_, err := store.Execute(context.Background(), request)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeArtifactHashMismatch {
		t.Fatalf("payload digest mismatch = %#v", err)
	}
	request = transactionRequest("request-b")
	request.ResultSHA256 = digestZero()
	_, err = store.Execute(context.Background(), request)
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeArtifactHashMismatch {
		t.Fatalf("result digest mismatch = %#v", err)
	}
}

func TestMemoryStoreRequiresExactlyOneEventPerProjectionUpdate(t *testing.T) {
	store := NewMemoryStore()
	missing := transactionRequest("missing-event")
	missing.Updates = append(missing.Updates, ProjectionUpdate{
		TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "task", AggregateID: "task_1",
		ExpectedVersion: 0, NextVersion: 1, State: []byte(`{"id":"task_1","version":1}`),
	})
	if _, err := store.Execute(context.Background(), missing); err == nil {
		t.Fatal("projection update without an immutable event was accepted")
	}

	duplicate := transactionRequest("duplicate-event")
	second := duplicate.Events[0]
	second.EventID = "evt_2"
	duplicate.Events = append(duplicate.Events, second)
	if _, err := store.Execute(context.Background(), duplicate); err == nil {
		t.Fatal("multiple events for one projection update were accepted")
	}
	if stats := store.Stats(); stats.Events != 0 || stats.Projections != 0 {
		t.Fatalf("invalid transactions mutated state: %#v", stats)
	}
}

func transactionRequest(requestID string) TransactionRequest {
	result := []byte(`{"projectId":"prj_1","version":1}`)
	payload := []byte(`{"projectId":"prj_1","aggregateVersion":1}`)
	resultDigest, _ := canonicaljson.Digest(result)
	payloadDigest, _ := canonicaljson.Digest(payload)
	return TransactionRequest{
		TenantID: "tenant_1", PrincipalID: "svc_orchestrator", IdempotencyKey: "idem_1", RequestSHA256: digestZero(), Result: result, ResultSHA256: resultDigest,
		Updates: []ProjectionUpdate{{TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", ExpectedVersion: 0, NextVersion: 1, State: []byte(`{"state":"GOAL_NEGOTIATING","version":1}`)}},
		Events:  []DomainEvent{{EventID: "evt_1", TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", AggregateVersion: 1, Type: "io.aor.project.created.v1", Payload: payload, PayloadSHA256: payloadDigest, OccurredAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), CorrelationID: requestID}},
	}
}

func projectionTransaction(tenantID, projectID, aggregateType, aggregateID string) TransactionRequest {
	state := []byte(`{"id":"` + aggregateID + `"}`)
	digest, _ := canonicaljson.Digest(state)
	return TransactionRequest{
		TenantID: tenantID, PrincipalID: "svc", IdempotencyKey: aggregateID, RequestSHA256: digestZero(), Result: state, ResultSHA256: digest,
		Updates: []ProjectionUpdate{{TenantID: tenantID, ProjectID: projectID, AggregateType: aggregateType, AggregateID: aggregateID, ExpectedVersion: 0, NextVersion: 1, State: state}},
		Events:  []DomainEvent{{EventID: "event-" + tenantID + "-" + projectID + "-" + aggregateID, TenantID: tenantID, ProjectID: projectID, AggregateType: aggregateType, AggregateID: aggregateID, AggregateVersion: 1, Type: "io.aor.test.v1", Payload: state, PayloadSHA256: digest, OccurredAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}},
	}
}

func digestZero() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func digestOne() string {
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}
