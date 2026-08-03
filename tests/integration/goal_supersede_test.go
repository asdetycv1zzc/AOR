package integration_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestGoalSupersedeChangesOnlyImpactedTasks(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newIntegrationOrchestrator(store)
	ctx := context.Background()
	prepareExecutingProject(t, ctx, service)
	ref := contracts.SpecRef{Version: 1, SHA256: replayDigest()}
	defineTask(t, ctx, service, "task_1", nil, ref)
	defineTask(t, ctx, service, "task_2", nil, ref)
	newGoal := state.GoalRecord{ID: "goal_1", Version: 2, SHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222"}
	outcome, err := service.HandleProject(ctx, orchestrator.ProjectRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "goal_change", ExpectedVersion: 5,
		Command: state.ProjectCommand{Type: state.ProjectCommandSupersedeGoal, Goal: &newGoal, ImpactedTaskIDs: []string{"task_1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Project.State != contracts.ProjectGoalNegotiating || outcome.Project.Plan != nil {
		t.Fatalf("superseded project = %#v", outcome.Project)
	}
	assertTaskState(t, ctx, store, "task_1", contracts.TaskSuperseded)
	assertTaskState(t, ctx, store, "task_2", contracts.TaskDefined)
}

func assertTaskState(t *testing.T, ctx context.Context, store *eventing.MemoryStore, taskID string, expected contracts.ModuleTaskState) {
	t.Helper()
	projection, found, err := store.Load(ctx, "tenant_1", "task", taskID)
	if err != nil || !found {
		t.Fatalf("task %s missing: %v", taskID, err)
	}
	var task state.ModuleTask
	if err := json.Unmarshal(projection.State, &task); err != nil {
		t.Fatal(err)
	}
	if task.State != expected {
		t.Fatalf("task %s state = %s, want %s", taskID, task.State, expected)
	}
}
