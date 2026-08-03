package agentruntime

import (
	"context"
	"sync"
	"testing"
	"time"
)

type slotAcquisition struct {
	id      string
	role    Role
	release func()
	err     error
}

func TestSlotPoolEnforcesHardLimitAndCancellation(t *testing.T) {
	pool, err := NewSlotPool(MaximumActiveAgentLimit, nil)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	var releases []func()
	for index := 0; index < MaximumActiveAgentLimit; index++ {
		release, acquireErr := pool.Acquire(context.Background(), RoleExecutor, 1)
		if acquireErr != nil {
			t.Fatalf("acquire %d: %v", index, acquireErr)
		}
		releases = append(releases, release)
	}
	if snapshot := pool.Snapshot(); snapshot.Active != MaximumActiveAgentLimit {
		t.Fatalf("active = %d", snapshot.Active)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, acquireErr := pool.Acquire(ctx, RoleGoalProposer, 1000)
		result <- acquireErr
	}()
	waitForWaiting(t, pool, 1)
	cancel()
	if acquireErr := <-result; !errorsIsContextCanceled(acquireErr) {
		t.Fatalf("canceled acquire error = %v", acquireErr)
	}
	for _, release := range releases {
		release()
		release()
	}
	if snapshot := pool.Snapshot(); snapshot.Active != 0 || snapshot.Waiting != 0 {
		t.Fatalf("pool leaked slots: %#v", snapshot)
	}
	if _, err := NewSlotPool(MaximumActiveAgentLimit+1, nil); err != ErrActiveLimit {
		t.Fatalf("oversized pool error = %v", err)
	}
}

func TestSlotPoolSoftLimitAndAging(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	pool, err := NewSlotPool(7, clock.Now)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	var releases []func()
	for index := 0; index < 6; index++ {
		release, acquireErr := pool.Acquire(context.Background(), RoleExecutor, 1)
		if acquireErr != nil {
			t.Fatalf("executor slot: %v", acquireErr)
		}
		releases = append(releases, release)
	}
	goalRelease, err := pool.Acquire(context.Background(), RoleGoalProposer, 1)
	if err != nil {
		t.Fatalf("goal slot: %v", err)
	}
	results := make(chan slotAcquisition, 2)
	go acquireForTest(pool, "executor", RoleExecutor, 1000, results)
	waitForWaiting(t, pool, 1)
	go acquireForTest(pool, "knowledge", RoleKnowledgeCurator, 1, results)
	waitForWaiting(t, pool, 2)
	goalRelease()
	first := <-results
	if first.err != nil || first.role != RoleKnowledgeCurator {
		t.Fatalf("soft-limit winner = %#v", first)
	}
	first.release()
	second := <-results
	if second.err != nil || second.role != RoleExecutor {
		t.Fatalf("borrowed slot winner = %#v", second)
	}
	second.release()
	for _, release := range releases {
		release()
	}

	agingPool, err := NewSlotPool(1, clock.Now)
	if err != nil {
		t.Fatalf("new aging pool: %v", err)
	}
	blocker, err := agingPool.Acquire(context.Background(), RoleExecutor, 1)
	if err != nil {
		t.Fatalf("aging blocker: %v", err)
	}
	agingResults := make(chan slotAcquisition, 2)
	go acquireForTest(agingPool, "aged", RoleExecutor, 1, agingResults)
	waitForWaiting(t, agingPool, 1)
	clock.Advance(20 * time.Minute)
	go acquireForTest(agingPool, "new", RoleExecutor, 10, agingResults)
	waitForWaiting(t, agingPool, 2)
	blocker()
	aged := <-agingResults
	if aged.err != nil || aged.id != "aged" {
		t.Fatalf("aged acquisition = %#v", aged)
	}
	aged.release()
	last := <-agingResults
	if last.err != nil {
		t.Fatalf("last acquisition: %v", last.err)
	}
	last.release()
}

func acquireForTest(pool *SlotPool, id string, role Role, priority int, output chan<- slotAcquisition) {
	release, err := pool.Acquire(context.Background(), role, priority)
	output <- slotAcquisition{id: id, role: role, release: release, err: err}
}

func waitForWaiting(t *testing.T, pool *SlotPool, expected int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pool.Snapshot().Waiting == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiting did not reach %d: %#v", expected, pool.Snapshot())
}

func errorsIsContextCanceled(err error) bool {
	return err == context.Canceled
}

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}
