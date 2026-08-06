package performance_test

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

// TestQueuedTasksRespectProjectConcurrency exercises the same global slot
// primitive used by workers with a production-sized queue. It is deliberately
// independent of model latency so a release report can separate scheduler
// capacity from provider performance.
func TestQueuedTasksRespectProjectConcurrency(t *testing.T) {
	pool, err := agentruntime.NewSlotPool(8, nil)
	if err != nil {
		t.Fatal(err)
	}
	const queued = 1000
	var active int32
	var maximum int32
	var completed int32
	var wait sync.WaitGroup
	wait.Add(queued)
	for index := 0; index < queued; index++ {
		go func() {
			defer wait.Done()
			release, acquireErr := pool.Acquire(context.Background(), agentruntime.RoleExecutor, 0)
			if acquireErr != nil {
				t.Errorf("acquire slot: %v", acquireErr)
				return
			}
			current := atomic.AddInt32(&active, 1)
			for {
				previous := atomic.LoadInt32(&maximum)
				if current <= previous || atomic.CompareAndSwapInt32(&maximum, previous, current) {
					break
				}
			}
			time.Sleep(time.Microsecond)
			atomic.AddInt32(&active, -1)
			atomic.AddInt32(&completed, 1)
			release()
		}()
	}
	wait.Wait()
	if completed != queued {
		t.Fatalf("completed=%d queued=%d", completed, queued)
	}
	if maximum > 8 {
		t.Fatalf("active concurrency exceeded limit: %d", maximum)
	}
}

func TestConcurrentProjectScopesRemainIsolated(t *testing.T) {
	store := eventing.NewMemoryStore()
	payload := json.RawMessage(`{"state":"EXECUTING"}`)
	payloadDigest, err := canonicaljson.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"ok":true}`)
	resultDigest, err := canonicaljson.Digest(result)
	if err != nil {
		t.Fatal(err)
	}
	const projects = 100
	var wait sync.WaitGroup
	wait.Add(projects)
	for index := 0; index < projects; index++ {
		go func(index int) {
			defer wait.Done()
			id := "project_" + strconv.Itoa(index)
			tenant := "tenant_" + strconv.Itoa(index)
			event := eventing.DomainEvent{
				EventID: "event_" + strconv.Itoa(index), TenantID: tenant, ProjectID: id,
				AggregateType: "project", AggregateID: id, AggregateVersion: 1,
				Type: "io.aor.project.updated.v1", Payload: payload, PayloadSHA256: payloadDigest,
				OccurredAt: time.Now().UTC(),
			}
			_, executeErr := store.Execute(context.Background(), eventing.TransactionRequest{
				TenantID: tenant, PrincipalID: "principal_" + strconv.Itoa(index),
				IdempotencyKey: "request_" + strconv.Itoa(index), RequestSHA256: payloadDigest,
				Updates: []eventing.ProjectionUpdate{{TenantID: tenant, ProjectID: id, AggregateType: "project", AggregateID: id, NextVersion: 1, State: payload}},
				Events:  []eventing.DomainEvent{event}, Result: result, ResultSHA256: resultDigest,
			})
			if executeErr != nil {
				t.Errorf("project %d execute: %v", index, executeErr)
			}
		}(index)
	}
	wait.Wait()
	for index := 0; index < projects; index++ {
		tenant := "tenant_" + strconv.Itoa(index)
		projections, listErr := store.ListTenantProjections(context.Background(), tenant)
		if listErr != nil || len(projections) != 1 || projections[0].TenantID != tenant {
			t.Fatalf("tenant %s projections=%#v err=%v", tenant, projections, listErr)
		}
	}
}
