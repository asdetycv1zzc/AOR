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

func digestZero() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func digestOne() string {
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}
