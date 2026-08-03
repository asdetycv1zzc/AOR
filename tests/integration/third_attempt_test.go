package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestThirdAttemptBlocksTaskAndDependantsAtomically(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := orchestrator.New(store, replayClock)
	ctx := context.Background()
	prepareExecutingProject(t, ctx, service)
	ref := contracts.SpecRef{Version: 1, SHA256: replayDigest()}
	defineTask(t, ctx, service, "task_2", nil, ref)
	defineTask(t, ctx, service, "task_3", nil, ref)
	main := defineTask(t, ctx, service, "task_1", []string{"task_2", "task_3"}, ref)
	main = taskStep(t, ctx, service, main, "ready_1", state.TaskCommand{Type: state.TaskCommandReadyExecution})
	for attempt := 1; attempt <= 3; attempt++ {
		main = taskStep(t, ctx, service, main, key("lease", attempt), state.TaskCommand{Type: state.TaskCommandLeaseExecution, FencingToken: int64(attempt)})
		main = taskStep(t, ctx, service, main, key("submit", attempt), state.TaskCommand{Type: state.TaskCommandSubmit, FencingToken: int64(attempt), ModuleSpecRef: ref, AttemptSeriesID: "series_task_1"})
		main = taskStep(t, ctx, service, main, key("audit", attempt), state.TaskCommand{Type: state.TaskCommandStartAudit, SubmissionValidated: true, AuditEvidenceSHA256: replayDigest()})
		main = taskStep(t, ctx, service, main, key("fail", attempt), state.TaskCommand{Type: state.TaskCommandDeterministicFailure, AuditEvidenceSHA256: replayDigest()})
		if attempt < 3 {
			main = taskStep(t, ctx, service, main, key("rework", attempt), state.TaskCommand{Type: state.TaskCommandQueueRework})
		}
	}
	if main.State != contracts.TaskBlockedUserDecision {
		t.Fatalf("main state = %s", main.State)
	}
	for _, taskID := range []string{"task_2", "task_3"} {
		projection, found, err := store.Load(ctx, "tenant_1", "task", taskID)
		if err != nil || !found {
			t.Fatalf("dependent %s missing: %v", taskID, err)
		}
		var dependent state.ModuleTask
		if err := json.Unmarshal(projection.State, &dependent); err != nil {
			t.Fatal(err)
		}
		if dependent.State != contracts.TaskBlockedDependency {
			t.Fatalf("dependent %s state = %s", taskID, dependent.State)
		}
	}
	approval := &state.ApprovalBinding{
		RecordID: "approval_attempt_reset", ApprovalType: "AUTHORIZE_NEW_ATTEMPT_SERIES", SubjectType: "MODULE_TASK", SubjectID: main.ID,
		SubjectVersion: main.ModuleSpecRef.Version, SubjectSHA256: main.ModuleSpecRef.SHA256, PrincipalID: "usr_1", Reason: "integration reset",
		IssuedAt: replayClock(), Signature: "integration-signature",
	}
	outcome, err := service.HandleTask(ctx, orchestrator.TaskRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", TaskID: main.ID, PrincipalID: "usr_1", IdempotencyKey: "authorize_new_series", ExpectedVersion: main.Version,
		Command: state.TaskCommand{Type: state.TaskCommandAuthorizeNewSeries, Decision: contracts.DecisionAuthorizeNewAttemptSeries, NewAttemptSeriesID: "series_task_1_reset", ModuleSpecRef: ref, Approval: approval},
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Task.State != contracts.TaskReadyExecution || outcome.Task.Attempt != 0 {
		t.Fatalf("authorized task = %#v", outcome.Task)
	}
	for _, taskID := range []string{"task_2", "task_3"} {
		projection, found, loadErr := store.Load(ctx, "tenant_1", "task", taskID)
		if loadErr != nil || !found {
			t.Fatalf("unblocked dependent %s missing: %v", taskID, loadErr)
		}
		var dependent state.ModuleTask
		if decodeErr := json.Unmarshal(projection.State, &dependent); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if dependent.State != contracts.TaskDefined || len(dependent.BlockingTaskIDs) != 0 {
			t.Fatalf("dependent %s not restored: %#v", taskID, dependent)
		}
	}
	if stats := store.Stats(); stats.Approvals != 2 {
		t.Fatalf("immutable approval count = %d", stats.Approvals)
	}
}

func prepareExecutingProject(t *testing.T, ctx context.Context, service *orchestrator.Service) {
	t.Helper()
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "project_create", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 2}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "svc_orchestrator", IdempotencyKey: "goal_start", ExpectedVersion: 1, Command: state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}}); err != nil {
		t.Fatal(err)
	}
	goal := state.GoalRecord{ID: "goal_1", Version: 1, SHA256: replayDigest()}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "agt_goal", IdempotencyKey: "goal_propose", ExpectedVersion: 2, Command: state.ProjectCommand{Type: state.ProjectCommandProposeGoal, Goal: &goal}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "goal_approve", ExpectedVersion: 3, Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: &goal, Approval: integrationGoalApproval(goal, "approval_1")}}); err != nil {
		t.Fatal(err)
	}
	plan := contracts.SpecRef{Version: 1, SHA256: replayDigest()}
	if _, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "agt_plan", IdempotencyKey: "plan_publish", ExpectedVersion: 4, Command: state.ProjectCommand{Type: state.ProjectCommandPublishPlan, GoalSpecRef: &plan, Plan: &plan, DAG: map[string][]string{"task_1": {}, "task_2": {}, "task_3": {}}}}); err != nil {
		t.Fatal(err)
	}
}

func integrationGoalApproval(goal state.GoalRecord, recordID string) *state.ApprovalBinding {
	return &state.ApprovalBinding{
		RecordID: recordID, ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: goal.ID,
		SubjectVersion: goal.Version, SubjectSHA256: goal.SHA256, PrincipalID: "usr_1", Reason: "integration approval",
		IssuedAt: replayClock(), Signature: "integration-signature",
	}
}

func defineTask(t *testing.T, ctx context.Context, service *orchestrator.Service, taskID string, dependants []string, ref contracts.SpecRef) state.ModuleTask {
	t.Helper()
	outcome, err := service.HandleTask(ctx, orchestrator.TaskRequest{TenantID: "tenant_1", ProjectID: "prj_1", TaskID: taskID, PrincipalID: "agt_plan", IdempotencyKey: "define_" + taskID, ExpectedVersion: 0, Command: state.TaskCommand{Type: state.TaskCommandDefine, ModuleSpecRef: ref, AttemptSeriesID: "series_" + taskID, DependentTaskIDs: dependants}})
	if err != nil {
		t.Fatal(err)
	}
	return outcome.Task
}

func taskStep(t *testing.T, ctx context.Context, service *orchestrator.Service, current state.ModuleTask, idempotencyKey string, command state.TaskCommand) state.ModuleTask {
	t.Helper()
	outcome, err := service.HandleTask(ctx, orchestrator.TaskRequest{TenantID: current.TenantID, ProjectID: current.ProjectID, TaskID: current.ID, PrincipalID: "agt_executor", IdempotencyKey: idempotencyKey, ExpectedVersion: current.Version, Command: command})
	if err != nil {
		t.Fatal(err)
	}
	return outcome.Task
}

func key(prefix string, attempt int) string {
	return fmt.Sprintf("%s_%d", prefix, attempt)
}
