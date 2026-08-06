package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type concurrentPassStore struct {
	*eventing.MemoryStore
	mu        sync.Mutex
	armed     bool
	arrived   int
	conflicts int
	release   chan struct{}
}

func (store *concurrentPassStore) arm() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.armed = true
	store.release = make(chan struct{})
}

func (store *concurrentPassStore) Execute(ctx context.Context, request eventing.TransactionRequest) (eventing.TransactionResult, error) {
	if containsEventType(request.Events, "io.aor.module.llm-audit-passed.v1") {
		store.mu.Lock()
		if store.armed && store.arrived < 2 {
			store.arrived++
			release := store.release
			if store.arrived == 2 {
				close(release)
			}
			store.mu.Unlock()
			select {
			case <-release:
			case <-ctx.Done():
				return eventing.TransactionResult{}, ctx.Err()
			}
		} else {
			store.mu.Unlock()
		}
	}
	result, err := store.MemoryStore.Execute(ctx, request)
	var typed *aorerrors.Error
	if errors.As(err, &typed) && typed.Code == aorerrors.CodeStateVersionConflict {
		store.mu.Lock()
		store.conflicts++
		store.mu.Unlock()
	}
	return result, err
}

func (store *concurrentPassStore) conflictCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.conflicts
}

func containsEventType(events []eventing.DomainEvent, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

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

func TestClassroomCoreSerializesConcurrentFinalPasses(t *testing.T) {
	store := &concurrentPassStore{MemoryStore: eventing.NewMemoryStore()}
	service := newTestService(store)
	service.coreOnly = true
	setupPlanningProject(t, service)
	request := validPublishPlanRequest()
	request.DAG = map[string][]string{"mod_left": {}, "mod_right": {}}
	request.Tasks = []PlanTaskDefinition{
		{ModuleID: "mod_left", TaskID: "task_left", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, AttemptSeriesID: "series_left"},
		{ModuleID: "mod_right", TaskID: "task_right", ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, AttemptSeriesID: "series_right"},
	}
	stagePlanTasks(t, service, request)
	outcome, err := service.PublishPlan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	tasks := make(map[string]state.ModuleTask, len(outcome.Tasks))
	for _, task := range outcome.Tasks {
		tasks[task.ID] = advanceTaskToLLMAudit(t, service, task, task.ID)
	}
	requests := []TaskRequest{
		auditPassTaskRequest(tasks["task_left"], "concurrent_left"),
		auditPassTaskRequest(tasks["task_right"], "concurrent_right"),
	}
	store.arm()

	type passResult struct {
		outcome TaskOutcome
		err     error
	}
	results := make(chan passResult, len(requests))
	for index := range requests {
		go func(index int) {
			passOutcome, passErr := service.HandleTask(context.Background(), requests[index])
			results <- passResult{outcome: passOutcome, err: passErr}
		}(index)
	}
	for range requests {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent pass error = %v", result.err)
		}
		if result.outcome.Task.State != contracts.TaskPassed {
			t.Fatalf("successful concurrent pass = %#v", result.outcome)
		}
	}
	if store.conflictCount() != 1 {
		t.Fatalf("project progress conflicts = %d", store.conflictCount())
	}
	project, found, err := service.Project(context.Background(), "tenant_1", "prj_1")
	if err != nil || !found || project.CoreSummary == nil {
		t.Fatalf("project summary = %#v found=%t err=%v", project.CoreSummary, found, err)
	}
	if len(project.CoreSummary.Modules) != 2 {
		t.Fatalf("project summary modules = %#v", project.CoreSummary.Modules)
	}
}
