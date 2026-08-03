package eventing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestOutboxPublisherRecoversWithoutLossAndDrainsConcurrently(t *testing.T) {
	const eventCount = 40
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &outboxTestClock{now: now}
	store := NewMemoryStore()
	for index := 0; index < eventCount; index++ {
		appendOutboxEvent(t, store, index, now)
	}
	bus := newRecoveringEventBus(false)
	publisher, err := NewOutboxPublisher(store, bus, OutboxPublisherConfig{
		BatchSize: 10, Concurrency: 4, ClaimTTL: 10 * time.Second, PublishTimeout: 5 * time.Second,
		InitialBackoff: time.Second, MaxBackoff: 8 * time.Second, Clock: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	for batch := 0; batch < 4; batch++ {
		result, err := publisher.RunOnce(context.Background(), "tenant_1")
		if err != nil {
			t.Fatal(err)
		}
		if result.Claimed != 10 || result.Published != 0 || result.Retried != 10 {
			t.Fatalf("outage batch %d = %#v", batch, result)
		}
	}
	if result, err := publisher.RunOnce(context.Background(), "tenant_1"); err != nil || result.Claimed != 0 {
		t.Fatalf("backoff claim = %#v, %v", result, err)
	}
	store.mu.Lock()
	for _, record := range store.outbox {
		if record.PublishedAt != nil || record.Attempts != 1 || !record.NextAttempt.Equal(now.Add(time.Second)) {
			store.mu.Unlock()
			t.Fatalf("record was lost or retried without backoff: %#v", record)
		}
	}
	store.mu.Unlock()

	clock.Advance(time.Second)
	gate := make(chan struct{})
	started := make(chan struct{}, eventCount)
	bus.Recover(gate, started)
	type runResult struct {
		batch PublishBatchResult
		err   error
	}
	results := make(chan runResult, 4)
	for worker := 0; worker < 4; worker++ {
		go func() {
			batch, runErr := publisher.RunOnce(context.Background(), "tenant_1")
			results <- runResult{batch: batch, err: runErr}
		}()
	}
	timer := time.NewTimer(2 * time.Second)
	for count := 0; count < 8; count++ {
		select {
		case <-started:
		case <-timer.C:
			close(gate)
			t.Fatal("publisher did not use configured concurrency")
		}
	}
	if !timer.Stop() {
		<-timer.C
	}
	close(gate)

	var recovered PublishBatchResult
	for worker := 0; worker < 4; worker++ {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		recovered.Claimed += result.batch.Claimed
		recovered.Published += result.batch.Published
		recovered.Retried += result.batch.Retried
	}
	if recovered.Claimed != eventCount || recovered.Published != eventCount || recovered.Retried != 0 {
		t.Fatalf("recovery result = %#v", recovered)
	}
	if bus.MaximumConcurrency() < 8 {
		t.Fatalf("maximum publish concurrency = %d", bus.MaximumConcurrency())
	}
	for index := 0; index < eventCount; index++ {
		eventID := fmt.Sprintf("evt_%03d", index)
		attempts, published := bus.Counts(eventID)
		if attempts != 2 || published != 1 {
			t.Fatalf("event %s attempts = %d, published = %d", eventID, attempts, published)
		}
	}
	if result, err := publisher.RunOnce(context.Background(), "tenant_1"); err != nil || result.Claimed != 0 {
		t.Fatalf("drained outbox = %#v, %v", result, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.outbox) != eventCount {
		t.Fatalf("retained outbox records = %d", len(store.outbox))
	}
	for _, record := range store.outbox {
		if record.PublishedAt == nil || record.Attempts != 2 {
			t.Fatalf("unpublished recovery record = %#v", record)
		}
	}
}

func TestMemoryOutboxStoreFencesExpiredClaims(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	appendOutboxEvent(t, store, 0, now)
	first, err := store.ClaimOutbox(context.Background(), "tenant_1", now, 1, time.Second)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim = %#v, %v", first, err)
	}
	second, err := store.ClaimOutbox(context.Background(), "tenant_1", now.Add(time.Second), 1, time.Second)
	if err != nil || len(second) != 1 || second[0].Attempt != 2 {
		t.Fatalf("second claim = %#v, %v", second, err)
	}
	if err := store.MarkOutboxPublished(context.Background(), "tenant_1", first[0].Record.ID, first[0].Attempt, now.Add(time.Second)); !errors.Is(err, ErrOutboxClaimLost) {
		t.Fatalf("stale claim result = %v", err)
	}
	if err := store.MarkOutboxPublished(context.Background(), "tenant_1", second[0].Record.ID, second[0].Attempt, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func appendOutboxEvent(t *testing.T, store *MemoryStore, index int, occurredAt time.Time) {
	t.Helper()
	request := transactionRequest(fmt.Sprintf("correlation_%03d", index))
	request.IdempotencyKey = fmt.Sprintf("idempotency_%03d", index)
	aggregateID := fmt.Sprintf("project_%03d", index)
	request.Updates[0].AggregateID = aggregateID
	request.Events[0].AggregateID = aggregateID
	request.Events[0].EventID = fmt.Sprintf("evt_%03d", index)
	request.Events[0].OccurredAt = occurredAt
	if _, err := store.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

type outboxTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *outboxTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *outboxTestClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type recoveringEventBus struct {
	mu                 sync.Mutex
	available          bool
	gate               <-chan struct{}
	started            chan<- struct{}
	attempts           map[string]int
	published          map[string]int
	active             int
	maximumConcurrency int
}

func newRecoveringEventBus(available bool) *recoveringEventBus {
	return &recoveringEventBus{available: available, attempts: make(map[string]int), published: make(map[string]int)}
}

func (b *recoveringEventBus) Publish(ctx context.Context, event DomainEvent) error {
	b.mu.Lock()
	b.attempts[event.EventID]++
	b.active++
	if b.active > b.maximumConcurrency {
		b.maximumConcurrency = b.active
	}
	available := b.available
	gate := b.gate
	started := b.started
	b.mu.Unlock()

	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		select {
		case <-ctx.Done():
			b.finishPublish(event.EventID, false)
			return ctx.Err()
		case <-gate:
		}
	}
	if !available {
		b.finishPublish(event.EventID, false)
		return errors.New("event bus unavailable")
	}
	b.finishPublish(event.EventID, true)
	return nil
}

func (b *recoveringEventBus) Recover(gate <-chan struct{}, started chan<- struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.available = true
	b.gate = gate
	b.started = started
}

func (b *recoveringEventBus) Counts(eventID string) (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempts[eventID], b.published[eventID]
}

func (b *recoveringEventBus) MaximumConcurrency() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maximumConcurrency
}

func (b *recoveringEventBus) finishPublish(eventID string, published bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active--
	if published {
		b.published[eventID]++
	}
}
