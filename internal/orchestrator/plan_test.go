package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestPublishPlanCommitsProjectAndTasksAtomically(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	setupPlanningProject(t, service)
	request := validPublishPlanRequest()
	for attempt := 0; attempt < 100; attempt++ {
		outcome, err := service.PublishPlan(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Duplicate != (attempt > 0) || outcome.Project.State != contracts.ProjectExecuting || len(outcome.Tasks) != 2 {
			t.Fatalf("attempt %d outcome = %#v", attempt, outcome)
		}
	}
	apiTask := findTask(t, service, store, "task_api")
	workerTask := findTask(t, service, store, "task_worker")
	if len(apiTask.DependentTaskIDs) != 1 || apiTask.DependentTaskIDs[0] != workerTask.ID {
		t.Fatalf("dependent IDs = %v", apiTask.DependentTaskIDs)
	}
	if stats := store.Stats(); stats.Projections != 3 || stats.Events != 7 || stats.Outbox != 7 {
		t.Fatalf("store stats = %#v", stats)
	}
}

func TestPublishPlanFailureLeavesNoPartialTasks(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	setupPlanningProject(t, service)
	store.FailNext(eventing.FailureBeforeCommit)
	if _, err := service.PublishPlan(context.Background(), validPublishPlanRequest()); !errors.Is(err, eventing.ErrInjectedFailure) {
		t.Fatalf("publish error = %v", err)
	}
	projectProjection, found, err := store.Load(context.Background(), "tenant_1", "project", "prj_1")
	if err != nil || !found {
		t.Fatalf("project load = found %v err %v", found, err)
	}
	project, err := decodeProject(projectProjection.State)
	if err != nil || project.State != contracts.ProjectPlanning {
		t.Fatalf("project = %#v err %v", project, err)
	}
	for _, taskID := range []string{"task_api", "task_worker"} {
		if _, found, err := store.Load(context.Background(), "tenant_1", "task", taskID); err != nil || found {
			t.Fatalf("task %s = found %v err %v", taskID, found, err)
		}
	}
}

func TestPublishPlanRejectsChangedIdempotentBundle(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	setupPlanningProject(t, service)
	request := validPublishPlanRequest()
	if _, err := service.PublishPlan(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Tasks[0].AttemptSeriesID = "series_changed"
	_, err := service.PublishPlan(context.Background(), request)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed duplicate = %#v", err)
	}
}

func setupPlanningProject(t *testing.T, service *Service) {
	t.Helper()
	commands := []ProjectRequest{
		{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "create", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 2}},
		{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "start", ExpectedVersion: 1, Command: state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}},
		{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "agt_goal", IdempotencyKey: "propose", ExpectedVersion: 2, Command: state.ProjectCommand{Type: state.ProjectCommandProposeGoal, Goal: &state.GoalRecord{ID: "goal_1", Version: 1, SHA256: validRef().SHA256}}},
		{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "approve", ExpectedVersion: 3, Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: &state.GoalRecord{ID: "goal_1", Version: 1, SHA256: validRef().SHA256}, Approval: &state.ApprovalBinding{RecordID: "approval_1", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: "goal_1", SubjectVersion: 1, SubjectSHA256: validRef().SHA256, PrincipalID: "usr_1", Reason: "approve goal", IssuedAt: fixedClock(), Signature: "signature"}}},
	}
	for _, command := range commands {
		if _, err := service.HandleProject(context.Background(), command); err != nil {
			t.Fatal(err)
		}
	}
}

func validPublishPlanRequest() PublishPlanRequest {
	return PublishPlanRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "agt_plan", IdempotencyKey: "publish_plan", ExpectedProjectVersion: 4,
		GoalSpecRef: contracts.SpecRef{Version: 1, SHA256: validRef().SHA256}, PlanRef: contracts.SpecRef{Version: 1, SHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		DAG: map[string][]string{"mod_api": {}, "mod_worker": {"mod_api"}},
		Tasks: []PlanTaskDefinition{
			{ModuleID: "mod_worker", TaskID: "task_worker", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222"}, AttemptSeriesID: "series_worker"},
			{ModuleID: "mod_api", TaskID: "task_api", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:3333333333333333333333333333333333333333333333333333333333333333"}, AttemptSeriesID: "series_api"},
		},
	}
}

func findTask(t *testing.T, _ *Service, store eventing.Store, id string) state.ModuleTask {
	t.Helper()
	projection, found, err := store.Load(context.Background(), "tenant_1", "task", id)
	if err != nil || !found {
		t.Fatalf("load task %s = found %v err %v", id, found, err)
	}
	task, err := decodeTask(projection.State)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
