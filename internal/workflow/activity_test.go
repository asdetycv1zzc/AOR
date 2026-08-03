package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestActivityExecutorDeduplicatesConcurrentAtLeastOnceAttempts(t *testing.T) {
	effect := &recordingEffect{started: make(chan struct{}), release: make(chan struct{})}
	executor := NewActivityExecutor(effect)
	identity := ActivityIdentity{TenantID: "tenant_1", WorkflowID: "workflow_1", ActivityID: "charge"}

	results := make(chan ActivityResult, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := executor.Execute(context.Background(), identity, []byte(`{"amount":42}`))
			results <- result
			errors <- err
		}()
	}
	<-effect.started
	close(effect.release)
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-results, <-results
	if effect.calls != 1 || first.IdempotencyKey == "" || first.IdempotencyKey != second.IdempotencyKey || first.Duplicate == second.Duplicate {
		t.Fatalf("unexpected concurrent activity results: calls=%d first=%#v second=%#v", effect.calls, first, second)
	}
}

func TestActivityExecutorRejectsChangedInputForScheduledActivity(t *testing.T) {
	executor := NewActivityExecutor(&recordingEffect{})
	identity := ActivityIdentity{TenantID: "tenant_1", WorkflowID: "workflow_1", ActivityID: "notify"}
	if _, err := executor.Execute(context.Background(), identity, []byte(`{"recipient":"one"}`)); err != nil {
		t.Fatal(err)
	}
	_, err := executor.Execute(context.Background(), identity, []byte(`{"recipient":"two"}`))
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed activity input was not rejected as an idempotency conflict: %v", err)
	}
}

func TestActivityExecutorReusesKeyAfterUnknownFailure(t *testing.T) {
	effect := &unknownResultEffect{}
	executor := NewActivityExecutor(effect)
	identity := ActivityIdentity{TenantID: "tenant_1", WorkflowID: "workflow_1", ActivityID: "provision"}
	if _, err := executor.Execute(context.Background(), identity, []byte(`{"resource":"worker"}`)); !errors.Is(err, errResultUnknown) {
		t.Fatalf("first result = %v, want unknown result", err)
	}
	_, err := executor.Execute(context.Background(), identity, []byte(`{"resource":"different"}`))
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("retry with changed input was not rejected: %v", err)
	}
	result, err := executor.Execute(context.Background(), identity, []byte(`{"resource":"worker"}`))
	if err != nil {
		t.Fatal(err)
	}
	if effect.calls != 2 || effect.effects != 1 || result.Duplicate || result.IdempotencyKey != effect.key {
		t.Fatalf("retry did not reuse the external idempotency key: calls=%d effects=%d result=%#v key=%q", effect.calls, effect.effects, result, effect.key)
	}
}

func TestActivityKeyDoesNotDependOnAttemptOrInputOrder(t *testing.T) {
	identity := ActivityIdentity{TenantID: "tenant_1", WorkflowID: "workflow_1", ActivityID: "publish"}
	firstKey, _, err := activityKeys(identity, []byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	secondKey, _, err := activityKeys(identity, []byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if firstKey != secondKey {
		t.Fatalf("activity key changed across equivalent attempts: %q != %q", firstKey, secondKey)
	}
}

type recordingEffect struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
}

func (e *recordingEffect) Execute(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	e.mu.Lock()
	e.calls++
	call := e.calls
	e.mu.Unlock()
	if call == 1 && e.started != nil {
		close(e.started)
		<-e.release
	}
	return []byte(`{"ok":true}`), nil
}

var errResultUnknown = errors.New("external effect may have completed")

type unknownResultEffect struct {
	calls   int
	effects int
	key     string
}

func (e *unknownResultEffect) Execute(_ context.Context, key string, _ json.RawMessage) (json.RawMessage, error) {
	e.calls++
	if e.key == "" {
		e.key = key
		e.effects++
		return nil, errResultUnknown
	}
	if key != e.key {
		return nil, errors.New("idempotency key changed on retry")
	}
	return []byte(`{"provisioned":true}`), nil
}
