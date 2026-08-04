package eventing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestOutboxDispatcherDrainsAllPendingTenantPartitions(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newPartitionedOutboxStore(now, "tenant_1", "tenant_2")
	bus := newRecoveringEventBus(true)
	publisher, err := NewOutboxPublisher(store, bus, OutboxPublisherConfig{BatchSize: 10, Concurrency: 2, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewOutboxDispatcher(store, publisher, OutboxDispatcherConfig{TenantBatchSize: 10, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatcher.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Tenants != 2 || result.Claimed != 2 || result.Published != 2 || result.Retried != 0 {
		t.Fatalf("dispatch result = %#v", result)
	}
	if pending, err := store.PendingOutboxTenants(context.Background(), now, 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending tenants = %#v, %v", pending, err)
	}
}

func TestOutboxDispatcherSurvivesTransientPublishFailure(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newPartitionedOutboxStore(now, "tenant_1")
	bus := newRecoveringEventBus(false)
	publisher, err := NewOutboxPublisher(store, bus, OutboxPublisherConfig{
		BatchSize: 1, Concurrency: 1, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond,
		PollInterval: time.Millisecond, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewOutboxDispatcher(store, publisher, OutboxDispatcherConfig{
		TenantBatchSize: 1, PollInterval: time.Millisecond, FailureBackoff: time.Millisecond,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := dispatcher.RunOnce(context.Background())
	if err != nil || first.Retried != 1 || first.Published != 0 {
		t.Fatalf("initial deferred dispatch = %#v, %v", first, err)
	}
	bus.Recover(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(ctx) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		pending, pendingErr := store.PendingOutboxTenants(context.Background(), now, 1)
		if pendingErr != nil {
			t.Fatal(pendingErr)
		}
		if len(pending) == 0 {
			break
		}
		select {
		case <-deadline.C:
			cancel()
			t.Fatal("dispatcher did not recover")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if !errors.Is(dispatcher.Ready(), ErrOutboxDispatcherNotRunning) {
		t.Fatalf("Ready() after stop = %v", dispatcher.Ready())
	}
}

type partitionedOutboxStore struct {
	*MemoryStore
	mu       sync.Mutex
	now      time.Time
	tenants  []string
	pending  map[string]bool
	attempts map[string]int
}

func newPartitionedOutboxStore(now time.Time, tenants ...string) *partitionedOutboxStore {
	store := &partitionedOutboxStore{MemoryStore: NewMemoryStore(), now: now, tenants: append([]string(nil), tenants...), pending: make(map[string]bool), attempts: make(map[string]int)}
	for _, tenantID := range tenants {
		store.pending[tenantID] = true
	}
	return store
}

func (store *partitionedOutboxStore) PendingOutboxTenants(_ context.Context, _ time.Time, limit int) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]string, 0, limit)
	for _, tenantID := range store.tenants {
		if store.pending[tenantID] {
			result = append(result, tenantID)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (store *partitionedOutboxStore) ClaimOutbox(_ context.Context, tenantID string, now time.Time, limit int, _ time.Duration) ([]OutboxClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.pending[tenantID] || limit < 1 {
		return nil, nil
	}
	store.attempts[tenantID]++
	attempt := store.attempts[tenantID]
	event := DomainEvent{
		EventID: tenantID + "-event", TenantID: tenantID, ProjectID: "project-1", AggregateType: "project",
		AggregateID: "project-1", AggregateVersion: 1, Type: "io.aor.project.created.v1",
		Payload: []byte(`{"projectId":"project-1","aggregateVersion":1}`), PayloadSHA256: digestZero(), OccurredAt: now,
	}
	return []OutboxClaim{{Record: OutboxRecord{ID: tenantID + "-outbox", Event: event, Attempts: attempt}, Attempt: attempt}}, nil
}

func (store *partitionedOutboxStore) MarkOutboxPublished(_ context.Context, tenantID, _ string, attempt int, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.attempts[tenantID] != attempt {
		return ErrOutboxClaimLost
	}
	store.pending[tenantID] = false
	return nil
}

func (store *partitionedOutboxStore) RetryOutbox(_ context.Context, tenantID, _ string, attempt int, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.attempts[tenantID] != attempt {
		return ErrOutboxClaimLost
	}
	return nil
}
