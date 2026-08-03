package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestTaskCommandCannotCrossProjectBoundary(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newIntegrationOrchestrator(store)
	ctx := context.Background()
	prepareProject(t, ctx, service, "prj_1", "one")
	prepareProject(t, ctx, service, "prj_2", "two")
	ref := contracts.SpecRef{Version: 1, SHA256: replayDigest()}
	task := defineProjectTask(t, ctx, service, "prj_1", "task_shared", ref)

	_, err := service.HandleTask(ctx, orchestrator.TaskRequest{
		TenantID: "tenant_1", ProjectID: "prj_2", TaskID: task.ID, PrincipalID: "agt_executor", IdempotencyKey: "cross_project", ExpectedVersion: task.Version,
		Command: state.TaskCommand{Type: state.TaskCommandReadyExecution},
	})
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeForbidden {
		t.Fatalf("cross-project task command = %#v", err)
	}
}

func prepareProject(t *testing.T, ctx context.Context, service *orchestrator.Service, projectID, keySuffix string) {
	t.Helper()
	steps := []struct {
		principal string
		version   int64
		command   state.ProjectCommand
	}{
		{"usr_1", 0, state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 1}},
		{"svc_orchestrator", 1, state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}},
	}
	for index, step := range steps {
		_, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: projectID, PrincipalID: step.principal, IdempotencyKey: keySuffix + string(rune('a'+index)), ExpectedVersion: step.version, Command: step.command})
		if err != nil {
			t.Fatal(err)
		}
	}
	goal := state.GoalRecord{ID: "goal_" + keySuffix, Version: 1, SHA256: replayDigest()}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: projectID, PrincipalID: "agt_goal", IdempotencyKey: keySuffix + "_goal", ExpectedVersion: 2, Command: state.ProjectCommand{Type: state.ProjectCommandProposeGoal, Goal: &goal}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: projectID, PrincipalID: "usr_1", IdempotencyKey: keySuffix + "_approve", ExpectedVersion: 3, Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: &goal, Approval: integrationGoalApproval(goal, "approval_"+keySuffix)}}); err != nil {
		t.Fatal(err)
	}
	plan := contracts.SpecRef{Version: 1, SHA256: replayDigest()}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: projectID, PrincipalID: "agt_plan", IdempotencyKey: keySuffix + "_plan", ExpectedVersion: 4, Command: state.ProjectCommand{Type: state.ProjectCommandPublishPlan, GoalSpecRef: &plan, Plan: &plan, DAG: map[string][]string{"task_shared": {}}}}); err != nil {
		t.Fatal(err)
	}
}

func defineProjectTask(t *testing.T, ctx context.Context, service *orchestrator.Service, projectID, taskID string, ref contracts.SpecRef) state.ModuleTask {
	t.Helper()
	outcome, err := service.HandleTask(ctx, orchestrator.TaskRequest{TenantID: "tenant_1", ProjectID: projectID, TaskID: taskID, PrincipalID: "agt_plan", IdempotencyKey: "define_" + projectID, ExpectedVersion: 0, Command: state.TaskCommand{Type: state.TaskCommandDefine, ModuleSpecRef: ref, AttemptSeriesID: "series_" + projectID}})
	if err != nil {
		t.Fatal(err)
	}
	return outcome.Task
}
