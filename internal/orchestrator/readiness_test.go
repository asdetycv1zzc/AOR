package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestAuditPassReadiesDependentOnlyAfterEveryUpstreamPasses(t *testing.T) {
	store, service, tasks := publishedDependencyPlan(t)
	left := passTask(t, service, tasks["task_left"], "left")
	if left.State != contracts.TaskPassed {
		t.Fatalf("left state = %s", left.State)
	}
	dependent := findTask(t, service, store, "task_dependent")
	if dependent.State != contracts.TaskDefined {
		t.Fatalf("dependent state after first upstream = %s", dependent.State)
	}

	right := advanceTaskToLLMAudit(t, service, tasks["task_right"], "right")
	request := auditPassTaskRequest(right, "right_llm")
	store.FailNext(eventing.FailureBeforeCommit)
	if _, err := service.HandleTask(context.Background(), request); !errors.Is(err, eventing.ErrInjectedFailure) {
		t.Fatalf("failed audit pass error = %v", err)
	}
	if storedRight := findTask(t, service, store, right.ID); storedRight.State != contracts.TaskLLMAudit {
		t.Fatalf("failed audit pass changed upstream = %#v", storedRight)
	}
	if dependent = findTask(t, service, store, dependent.ID); dependent.State != contracts.TaskDefined {
		t.Fatalf("failed audit pass changed dependent = %#v", dependent)
	}

	outcome, err := service.HandleTask(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Task.State != contracts.TaskPassed || len(outcome.Events) != 2 {
		t.Fatalf("final audit pass outcome = %#v", outcome)
	}
	dependent = findTask(t, service, store, "task_dependent")
	if dependent.State != contracts.TaskReadyExecution || dependent.Version != 4 {
		t.Fatalf("ready dependent = %#v", dependent)
	}
}

func TestAuditPassPreservesNonDefinedDependentState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *Service, state.ModuleTask) state.ModuleTask
		want    contracts.ModuleTaskState
	}{
		{
			name: "blocked",
			prepare: func(t *testing.T, service *Service, task state.ModuleTask) state.ModuleTask {
				return taskCommand(t, service, task, "block_dependent", state.TaskCommand{Type: state.TaskCommandBlockDependency, BlockingTaskID: "external_blocker"})
			},
			want: contracts.TaskBlockedDependency,
		},
		{
			name: "rework",
			prepare: func(t *testing.T, service *Service, task state.ModuleTask) state.ModuleTask {
				task = taskCommand(t, service, task, "dependent_ready", state.TaskCommand{Type: state.TaskCommandReadyExecution})
				task = taskCommand(t, service, task, "dependent_lease", state.TaskCommand{Type: state.TaskCommandLeaseExecution, FencingToken: 1})
				task = taskCommand(t, service, task, "dependent_submit", state.TaskCommand{Type: state.TaskCommandSubmit, FencingToken: 1, ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: task.AttemptSeriesID})
				task = taskCommand(t, service, task, "dependent_audit", state.TaskCommand{Type: state.TaskCommandStartAudit, SubmissionValidated: true, AuditEvidenceSHA256: validRef().SHA256})
				return taskCommand(t, service, task, "dependent_fail", state.TaskCommand{Type: state.TaskCommandDeterministicFailure, AuditEvidenceSHA256: validRef().SHA256})
			},
			want: contracts.TaskReworkRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, service, tasks := publishedDependencyPlan(t)
			dependent := test.prepare(t, service, tasks["task_dependent"])
			passTask(t, service, tasks["task_left"], test.name+"_left")
			passTask(t, service, tasks["task_right"], test.name+"_right")

			stored := findTask(t, service, store, dependent.ID)
			if stored.State != test.want || stored.Version != dependent.Version {
				t.Fatalf("preserved dependent = %#v, want state %s version %d", stored, test.want, dependent.Version)
			}
		})
	}
}

func publishedDependencyPlan(t *testing.T) (*eventing.MemoryStore, *Service, map[string]state.ModuleTask) {
	t.Helper()
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	setupPlanningProject(t, service)
	request := validPublishPlanRequest()
	request.DAG = map[string][]string{"mod_left": {}, "mod_right": {}, "mod_dependent": {"mod_left", "mod_right"}}
	request.Tasks = []PlanTaskDefinition{
		{ModuleID: "mod_left", TaskID: "task_left", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, AttemptSeriesID: "series_left"},
		{ModuleID: "mod_right", TaskID: "task_right", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, AttemptSeriesID: "series_right"},
		{ModuleID: "mod_dependent", TaskID: "task_dependent", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, AttemptSeriesID: "series_dependent"},
	}
	stagePlanTasks(t, service, request)
	outcome, err := service.PublishPlan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	tasks := make(map[string]state.ModuleTask, len(outcome.Tasks))
	for _, task := range outcome.Tasks {
		tasks[task.ID] = task
	}
	if tasks["task_left"].State != contracts.TaskReadyExecution || tasks["task_right"].State != contracts.TaskReadyExecution || tasks["task_dependent"].State != contracts.TaskDefined {
		t.Fatalf("published tasks = %#v", tasks)
	}
	return store, service, tasks
}

func passTask(t *testing.T, service *Service, task state.ModuleTask, key string) state.ModuleTask {
	t.Helper()
	task = advanceTaskToLLMAudit(t, service, task, key)
	return taskCommand(t, service, task, key+"_llm", state.TaskCommand{Type: state.TaskCommandLLMSuccess, FreshAuditor: true, BlindAuditContext: true, NoBlockingFindings: true, AuditEvidenceSHA256: validRef().SHA256})
}

func advanceTaskToLLMAudit(t *testing.T, service *Service, task state.ModuleTask, key string) state.ModuleTask {
	t.Helper()
	task = taskCommand(t, service, task, key+"_lease", state.TaskCommand{Type: state.TaskCommandLeaseExecution, FencingToken: 1})
	task = taskCommand(t, service, task, key+"_submit", state.TaskCommand{Type: state.TaskCommandSubmit, FencingToken: 1, ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: task.AttemptSeriesID})
	task = taskCommand(t, service, task, key+"_audit", state.TaskCommand{Type: state.TaskCommandStartAudit, SubmissionValidated: true, AuditEvidenceSHA256: validRef().SHA256})
	return taskCommand(t, service, task, key+"_deterministic", state.TaskCommand{Type: state.TaskCommandDeterministicSuccess, AuditEvidenceSHA256: validRef().SHA256})
}

func auditPassTaskRequest(task state.ModuleTask, key string) TaskRequest {
	return TaskRequest{
		TenantID: task.TenantID, ProjectID: task.ProjectID, TaskID: task.ID, PrincipalID: "agt_auditor", IdempotencyKey: key, ExpectedVersion: task.Version,
		Command: state.TaskCommand{Type: state.TaskCommandLLMSuccess, FreshAuditor: true, BlindAuditContext: true, NoBlockingFindings: true, AuditEvidenceSHA256: validRef().SHA256},
	}
}

func taskCommand(t *testing.T, service *Service, task state.ModuleTask, key string, command state.TaskCommand) state.ModuleTask {
	t.Helper()
	outcome, err := service.HandleTask(context.Background(), TaskRequest{
		TenantID: task.TenantID, ProjectID: task.ProjectID, TaskID: task.ID, PrincipalID: "agt_executor", IdempotencyKey: key, ExpectedVersion: task.Version, Command: command,
	})
	if err != nil {
		t.Fatal(err)
	}
	return outcome.Task
}
