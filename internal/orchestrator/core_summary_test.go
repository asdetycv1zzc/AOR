package orchestrator

import (
	"context"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestClassroomCorePublishesSummaryAfterAllModulesPass(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	service.coreOnly = true
	setupPlanningProject(t, service)
	request := validPublishPlanRequest()
	request.DAG = map[string][]string{"mod_only": {}}
	request.Tasks = []PlanTaskDefinition{{
		ModuleID: "mod_only", TaskID: "task_only",
		ModuleSpecRef:   contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		AttemptSeriesID: "series_only",
	}}
	stagePlanTasks(t, service, request)
	if _, err := service.PublishPlan(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	task, found, err := service.Task(context.Background(), "tenant_1", "prj_1", "task_only")
	if err != nil || !found {
		t.Fatalf("task lookup = %#v found=%t err=%v", task, found, err)
	}
	passTask(t, service, task, "core")
	project, found, err := service.Project(context.Background(), "tenant_1", "prj_1")
	if err != nil || !found || project.CoreSummary == nil {
		t.Fatalf("project summary = %#v found=%t err=%v", project.CoreSummary, found, err)
	}
	if project.State != contracts.ProjectExecuting || project.CoreSummary.Status != "COMPLETED" || len(project.CoreSummary.Modules) != 1 || project.CoreSummary.Modules[0].TaskID != "task_only" {
		t.Fatalf("project core result = %#v", project)
	}
}

func TestClassroomCoreDoesNotSummarizeWhileAnyModuleIsPending(t *testing.T) {
	_, service, tasks := publishedDependencyPlan(t)
	service.coreOnly = true
	passTask(t, service, tasks["task_left"], "pending_left")
	project, found, err := service.Project(context.Background(), "tenant_1", "prj_1")
	if err != nil || !found {
		t.Fatal(err)
	}
	if project.CoreSummary != nil {
		t.Fatalf("summary published before dependent modules passed: %#v", project.CoreSummary)
	}
}
