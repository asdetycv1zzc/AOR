package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/contracts"
)

const (
	executionTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	executionPlanDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	executionGoalDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	executionBaseCommit = "1111111111111111111111111111111111111111"
	executionHeadCommit = "2222222222222222222222222222222222222222"
)

type testTaskAuthority struct {
	project     state.Project
	task        state.ModuleTask
	tasks       []state.ModuleTask
	leaseCalls  int
	submitCalls int
}

func (authority *testTaskAuthority) Project(context.Context, string, string) (state.Project, bool, error) {
	return authority.project, true, nil
}

func (authority *testTaskAuthority) Task(context.Context, string, string, string) (state.ModuleTask, bool, error) {
	return authority.task, true, nil
}

func (authority *testTaskAuthority) Tasks(context.Context, string, string) ([]state.ModuleTask, error) {
	result := append([]state.ModuleTask(nil), authority.tasks...)
	for index := range result {
		if result[index].ID == authority.task.ID {
			result[index] = authority.task
		}
	}
	return result, nil
}

func (authority *testTaskAuthority) LeaseExecution(_ context.Context, request LeaseTaskRequest) (state.ModuleTask, bool, error) {
	authority.leaseCalls++
	if request.ExpectedVersion != authority.task.Version || request.FencingToken <= authority.task.FencingToken {
		return state.ModuleTask{}, false, ErrAssignmentInvalid
	}
	event, err := state.DecideTask(authority.task, state.TaskCommand{Type: state.TaskCommandLeaseExecution, FencingToken: request.FencingToken, At: executionTestTime()})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	authority.task = event.Projection
	return authority.task, false, nil
}

func (authority *testTaskAuthority) SubmitExecution(_ context.Context, request SubmitTaskRequest) (state.ModuleTask, bool, error) {
	authority.submitCalls++
	if request.ExpectedVersion != authority.task.Version || request.FencingToken != authority.task.FencingToken || request.ModuleSpecRef != authority.task.ModuleSpecRef || request.AttemptSeriesID != authority.task.AttemptSeriesID || request.Submission.Attempt != authority.task.Attempt+1 {
		return state.ModuleTask{}, false, ErrSubmissionInvalid
	}
	event, err := state.DecideTask(authority.task, state.TaskCommand{
		Type: state.TaskCommandSubmit, FencingToken: request.FencingToken,
		ModuleSpecRef: request.ModuleSpecRef, AttemptSeriesID: request.AttemptSeriesID, At: executionTestTime(),
	})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	authority.task = event.Projection
	return authority.task, false, nil
}

type testModuleSpecs struct{ module contracts.ModuleSpec }

func (source testModuleSpecs) ModuleSpec(context.Context, string, string, string, contracts.SpecRef) (contracts.ModuleSpec, error) {
	return source.module, nil
}

type testAssignments struct {
	assignment Assignment
	calls      int
}

func (authority *testAssignments) Assign(_ context.Context, _ AssignmentRequest) (Assignment, error) {
	authority.calls++
	return authority.assignment, nil
}

type testPreparer struct {
	prepare func(PreparationRequest) PreparedRun
	calls   int
}

func (preparer *testPreparer) Prepare(_ context.Context, request PreparationRequest) (PreparedRun, error) {
	preparer.calls++
	return preparer.prepare(request), nil
}

type testRuntime struct {
	content      json.RawMessage
	declared     int
	toolLoops    int
	completed    int
	failed       int
	declaration  agentruntime.Declaration
	lease        agentruntime.AgentLease
	accepted     agentruntime.AcceptedResult
	acceptedSeen bool
}

func (runtime *testRuntime) Declare(declaration agentruntime.Declaration) error {
	runtime.declared++
	runtime.declaration = declaration
	return nil
}

func (runtime *testRuntime) Queue(string) error { return nil }

func (runtime *testRuntime) AssignLease(_ context.Context, _ string, lease agentruntime.AgentLease) error {
	runtime.lease = lease
	return nil
}

func (runtime *testRuntime) Start(context.Context, string) error { return nil }

func (runtime *testRuntime) Heartbeat(context.Context, string) error { return nil }

func (runtime *testRuntime) RunToolLoop(context.Context, string, agentruntime.ModelCall, int) (modelgateway.NormalizedResponse, error) {
	runtime.toolLoops++
	return modelgateway.NormalizedResponse{Content: append(json.RawMessage(nil), runtime.content...), FinishReason: "stop"}, nil
}

func (runtime *testRuntime) Complete(_ context.Context, runID string, output agentruntime.AgentOutput) (agentruntime.AcceptedResult, error) {
	runtime.completed++
	runtime.accepted = agentruntime.AcceptedResult{
		RunID: runID, Intent: output.Intent, Payload: append(json.RawMessage(nil), output.Payload...),
		ExpectedAggregateVersion: runtime.declaration.Envelope.ExpectedAggregateVersion,
		LeaseID:                  runtime.lease.LeaseID, FencingToken: runtime.lease.FencingToken,
	}
	runtime.acceptedSeen = true
	return runtime.accepted, nil
}

func (runtime *testRuntime) AcceptedResult(string) (agentruntime.AcceptedResult, bool) {
	return runtime.accepted, runtime.acceptedSeen
}

func (runtime *testRuntime) Fail(string) error {
	runtime.failed++
	return nil
}

type testBases struct{ base string }

func (resolver testBases) ResolveWorkspaceBaseCommit(context.Context, string, string, string, string, int) (string, error) {
	return resolver.base, nil
}

type testSubmissions struct{ submission *repository.Submission }

func (source *testSubmissions) Submission(context.Context, string, string, string, int) (repository.Submission, bool, error) {
	if source.submission == nil {
		return repository.Submission{}, false, nil
	}
	return *source.submission, true, nil
}

func TestServiceExecutesReadyTaskThroughRepositorySubmission(t *testing.T) {
	project, task, module := executionTestScope(contracts.TaskReadyExecution)
	manifest := executionTestManifest(task, 1, executionBaseCommit, "agent-1", "lease-1")
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	submission := executionTestSubmission(task, manifest)
	tasks := &testTaskAuthority{project: project, task: task, tasks: []state.ModuleTask{task}}
	assignments := &testAssignments{assignment: Assignment{AgentInstanceID: "agent-1", SandboxID: "sandbox-1", FencingToken: 7}}
	preparer := &testPreparer{prepare: executionPreparedRun}
	runtime := &testRuntime{content: content}
	service := executionTestService(t, tasks, module, assignments, preparer, runtime, &testSubmissions{submission: &submission})

	result, err := service.Execute(context.Background(), executionTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Task.State != contracts.TaskSubmitted || result.Task.Attempt != 1 || result.FencingToken != 7 || result.AgentInstanceID != "agent-1" || result.LeaseID != "lease-1" || result.SandboxID != "sandbox-1" || result.Duplicate {
		t.Fatalf("result = %#v", result)
	}
	if assignments.calls != 1 || tasks.leaseCalls != 1 || tasks.submitCalls != 1 || preparer.calls != 1 || runtime.toolLoops != 1 || runtime.completed != 1 || runtime.failed != 0 {
		t.Fatalf("assignment=%d lease=%d submit=%d prepare=%d loop=%d complete=%d fail=%d", assignments.calls, tasks.leaseCalls, tasks.submitCalls, preparer.calls, runtime.toolLoops, runtime.completed, runtime.failed)
	}
}

func TestServiceRejectsUnauditedDeclaredDependencyBeforeAssignment(t *testing.T) {
	project, task, module := executionTestScope(contracts.TaskReadyExecution)
	module.Dependencies = []string{"module-dependency"}
	dependency := state.ModuleTask{
		TenantID: task.TenantID, ProjectID: task.ProjectID, ID: "task-dependency", ModuleID: "module-dependency",
		State: contracts.TaskLLMAudit, ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: "series-dependency",
		DependentTaskIDs: []string{task.ID},
	}
	tasks := &testTaskAuthority{project: project, task: task, tasks: []state.ModuleTask{task, dependency}}
	assignments := &testAssignments{assignment: Assignment{AgentInstanceID: "agent-1", SandboxID: "sandbox-1", FencingToken: 7}}
	service := executionTestService(t, tasks, module, assignments, &testPreparer{prepare: executionPreparedRun}, &testRuntime{}, &testSubmissions{})

	_, err := service.Execute(context.Background(), executionTestRequest())
	if !errors.Is(err, ErrDependencyNotReady) || assignments.calls != 0 || tasks.leaseCalls != 0 {
		t.Fatalf("err=%v assignments=%d leases=%d", err, assignments.calls, tasks.leaseCalls)
	}
}

func TestValidateDependenciesAcceptsAuditedDependency(t *testing.T) {
	_, task, module := executionTestScope(contracts.TaskReadyExecution)
	module.Dependencies = []string{"module-dependency"}
	dependency := state.ModuleTask{
		TenantID: task.TenantID, ProjectID: task.ProjectID, ID: "task-dependency", ModuleID: "module-dependency",
		State: contracts.TaskPassed, DependentTaskIDs: []string{task.ID},
	}
	if err := validateDependencies(task, module, []state.ModuleTask{task, dependency}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRecoversSignedSubmissionWithoutRerunningExecutor(t *testing.T) {
	project, task, module := executionTestScope(contracts.TaskExecuting)
	task.FencingToken = 7
	manifest := executionTestManifest(task, 1, executionBaseCommit, "agent-1", "lease-1")
	submission := executionTestSubmission(task, manifest)
	tasks := &testTaskAuthority{project: project, task: task, tasks: []state.ModuleTask{task}}
	assignments := &testAssignments{}
	preparer := &testPreparer{prepare: executionPreparedRun}
	runtime := &testRuntime{}
	service := executionTestService(t, tasks, module, assignments, preparer, runtime, &testSubmissions{submission: &submission})

	result, err := service.Execute(context.Background(), executionTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Duplicate || result.Task.State != contracts.TaskSubmitted || assignments.calls != 0 || preparer.calls != 0 || runtime.declared != 0 || tasks.submitCalls != 1 {
		t.Fatalf("result=%#v assignments=%d prepare=%d runtime=%d submit=%d", result, assignments.calls, preparer.calls, runtime.declared, tasks.submitCalls)
	}
}

func TestServiceRejectsPreparedLeaseWithDifferentFence(t *testing.T) {
	project, task, module := executionTestScope(contracts.TaskReadyExecution)
	tasks := &testTaskAuthority{project: project, task: task, tasks: []state.ModuleTask{task}}
	assignments := &testAssignments{assignment: Assignment{AgentInstanceID: "agent-1", SandboxID: "sandbox-1", FencingToken: 7}}
	preparer := &testPreparer{prepare: func(request PreparationRequest) PreparedRun {
		prepared := executionPreparedRun(request)
		prepared.Lease.FencingToken++
		return prepared
	}}
	runtime := &testRuntime{}
	service := executionTestService(t, tasks, module, assignments, preparer, runtime, &testSubmissions{})

	_, err := service.Execute(context.Background(), executionTestRequest())
	if !errors.Is(err, ErrPreparationInvalid) || runtime.declared != 0 || tasks.task.State != contracts.TaskExecuting {
		t.Fatalf("err=%v runtime=%d task=%s", err, runtime.declared, tasks.task.State)
	}
}

func executionTestService(t *testing.T, tasks *testTaskAuthority, module contracts.ModuleSpec, assignments *testAssignments, preparer *testPreparer, runtime *testRuntime, submissions *testSubmissions) *Service {
	t.Helper()
	service, err := New(Config{
		Tasks: tasks, Specs: testModuleSpecs{module: module}, Assignments: assignments,
		Preparer: preparer, Runtime: runtime, Bases: testBases{base: executionBaseCommit}, Submissions: submissions,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func executionTestScope(taskState contracts.ModuleTaskState) (state.Project, state.ModuleTask, contracts.ModuleSpec) {
	planRef := contracts.SpecRef{Version: 1, SHA256: executionPlanDigest}
	moduleRef := contracts.SpecRef{Version: 1, SHA256: executionTestDigest}
	project := state.Project{
		TenantID: "tenant-1", ID: "project-1", State: contracts.ProjectExecuting, Version: 5,
		Goal: &state.GoalRecord{ID: "goal-1", Version: 1, SHA256: executionGoalDigest, Status: contracts.GoalApproved, ApprovedBy: "user-1"}, Plan: &planRef,
	}
	task := state.ModuleTask{
		TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", ModuleID: "module-1",
		State: taskState, Version: 4, ModuleSpecRef: moduleRef, AttemptSeriesID: "series-1", AttemptSeriesIDs: []string{"series-1"},
	}
	module := contracts.ModuleSpec{
		ModuleSpecVersion: 1, ModuleID: "module-1", ProjectID: "project-1", PlanVersion: 1,
		Name: "module", Purpose: "implement module", Responsibilities: []string{"implementation"},
		AllowedPaths: []string{"internal/module/**"}, ForbiddenPaths: []string{},
		ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer,
		NetworkPolicy:      contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll, Destinations: []string{}},
		WorkloadProfile:    contracts.WorkloadProfile{Trust: contracts.WorkloadTrusted},
		AcceptanceCriteria: []string{"works"}, TestRequirements: []string{"go test"},
		SecurityRequirements: []string{"owned paths"}, SHA256: executionTestDigest,
	}
	return project, task, module
}

func executionPreparedRun(request PreparationRequest) PreparedRun {
	goalRef := contracts.SpecRef{Version: request.Project.Goal.Version, SHA256: request.Project.Goal.SHA256}
	planRef := *request.Project.Plan
	moduleRef := request.Task.ModuleSpecRef
	lease := agentruntime.AgentLease{
		LeaseID: "lease-1", AgentInstanceID: request.Assignment.AgentInstanceID,
		TenantID: request.Task.TenantID, ProjectID: request.Task.ProjectID, TaskID: request.Task.ID,
		Role: agentruntime.RoleExecutor, FencingToken: request.Task.FencingToken,
		Capabilities: []string{"model.generate"},
	}
	tools := []modelgateway.ToolDefinition{
		{Name: RepositoryCreateWorkspace, Version: "1.0.0"}, {Name: RepositoryReadFile, Version: "1.0.0"},
		{Name: RepositoryWriteFile, Version: "1.0.0"}, {Name: RepositoryDeleteFile, Version: "1.0.0"},
		{Name: RepositorySubmit, Version: "1.0.0"},
	}
	return PreparedRun{
		Declaration: agentruntime.Declaration{
			RunID: request.ExecutionID, TenantID: request.Task.TenantID, ProjectID: request.Task.ProjectID,
			TaskID: request.Task.ID, AgentInstanceID: request.Assignment.AgentInstanceID, Role: agentruntime.RoleExecutor,
			Envelope: aop.Envelope{
				ProjectID: request.Task.ProjectID, GoalSpec: &goalRef, PlanSpec: &planRef, ModuleSpec: &moduleRef,
				TaskID: request.Task.ID, AttemptSeriesID: request.Task.AttemptSeriesID, Attempt: request.Attempt,
				Scope: aop.ScopeTask, Intent: aop.IntentSubmitImplementation, ExpectedAggregateVersion: request.Task.Version,
				Sender: aop.Sender{AgentInstanceID: request.Assignment.AgentInstanceID, Role: string(agentruntime.RoleExecutor), LeaseID: lease.LeaseID},
			},
			Tools: tools,
		},
		Lease: lease, ModelCall: agentruntime.ModelCall{RequestID: "model-call-1"}, MaxToolRounds: 4,
	}
}

func executionTestManifest(task state.ModuleTask, attempt int, baseCommit, agentID, leaseID string) contracts.SubmissionManifest {
	return contracts.SubmissionManifest{
		SubmissionVersion: 1, ProjectID: task.ProjectID, ModuleTaskID: task.ID,
		AttemptSeriesID: task.AttemptSeriesID, Attempt: attempt, ModuleSpecRef: task.ModuleSpecRef,
		BaseCommit: baseCommit, HeadCommit: executionHeadCommit, ChangedFiles: []string{"internal/module/file.go"},
		CreatedFiles: []string{"internal/module/file.go"}, ClaimedCriteria: []string{"works"},
		AgentIdentity: contracts.AgentIdentity{AgentInstanceID: agentID, Role: string(agentruntime.RoleExecutor), LeaseID: leaseID},
		CreatedAt:     executionTestTime().Format(time.RFC3339), SHA256: executionTestDigest,
		Signature: &contracts.Signature{Type: "test", KID: "test", JWS: "signed"},
	}
}

func executionTestSubmission(task state.ModuleTask, manifest contracts.SubmissionManifest) repository.Submission {
	return repository.Submission{
		Manifest: manifest,
		Workspace: repository.Workspace{
			ID: "workspace-1", TenantID: task.TenantID, ProjectID: task.ProjectID, TaskID: task.ID,
			Attempt: manifest.Attempt, AttemptSeriesID: task.AttemptSeriesID, BaseCommit: manifest.BaseCommit,
			ModuleSpecRef: task.ModuleSpecRef, AgentIdentity: manifest.AgentIdentity,
		},
	}
}

func executionTestRequest() Request {
	return Request{ExecutionID: "execution-1", TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1"}
}

func executionTestTime() time.Time {
	return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
}
