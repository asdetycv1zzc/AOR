package servicebootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/audit"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/execution"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	temporalworkflow "go.temporal.io/sdk/workflow"
)

type workerSandboxProvider struct {
	created    bool
	destroyed  bool
	exported   bool
	destroyErr error
}

type workerSandboxAuthorizer struct {
	calls int
	err   error
}

type moduleAuditRunnerStub struct {
	result   audit.ModuleAuditResult
	err      error
	requests []audit.ModuleAuditRequest
}

func (runner *moduleAuditRunnerStub) Run(_ context.Context, request audit.ModuleAuditRequest) (audit.ModuleAuditResult, error) {
	runner.requests = append(runner.requests, request)
	return runner.result, runner.err
}

type planCompletionPublisherStub struct {
	result   goalplan.PlanCompletionResult
	err      error
	requests []goalplan.PlanCompletionRequest
}

type executionRunnerStub struct {
	principal    authn.Principal
	hasPrincipal bool
	requests     []execution.Request
}

func (runner *executionRunnerStub) Execute(ctx context.Context, request execution.Request) (execution.Result, error) {
	runner.principal, runner.hasPrincipal = authn.PrincipalFromContext(ctx)
	runner.requests = append(runner.requests, request)
	return execution.Result{}, nil
}

func (publisher *planCompletionPublisherStub) Publish(_ context.Context, request goalplan.PlanCompletionRequest) (goalplan.PlanCompletionResult, error) {
	publisher.requests = append(publisher.requests, request)
	return publisher.result, publisher.err
}

func (authorizer *workerSandboxAuthorizer) Authorize(context.Context, aorworkflow.ExecutionInput, sandboxActivityInput) error {
	authorizer.calls++
	return authorizer.err
}

func TestLinuxExecutionProviderRequiresPinnedDedicatedEngine(t *testing.T) {
	_, err := newExecutionProvider(runtimeconfig.Config{Sandbox: runtimeconfig.SandboxConfig{
		RuntimeName:       "runc",
		SeccompProfile:    "builtin",
		MandatoryPolicy:   "apparmor=aor-sandbox",
		HoldCommand:       []string{"/bin/sh"},
		AllowedMountRoots: []string{"/var/lib/aor/sandbox-data"},
	}})
	if !errors.Is(err, ErrWorkerConfiguration) && !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("missing Linux engine configuration error = %v", err)
	}
}

func TestModuleAuditActivityPublishesPlanCompletionAfterSuccessfulAudit(t *testing.T) {
	runID := uuid.Must(uuid.NewV7()).String()
	input := aorworkflow.ExecutionInput{TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1"}
	runner := &moduleAuditRunnerStub{result: audit.ModuleAuditResult{Duplicate: true}}
	completion := &planCompletionPublisherStub{result: goalplan.PlanCompletionResult{Published: false}}
	activity := &moduleAuditActivity{service: runner, completion: completion, local: true}

	result, err := activity.Run(context.Background(), input, runID)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Duplicate || len(runner.requests) != 1 || runner.requests[0].AuditRunID != runID || runner.requests[0].TaskID != input.TaskID {
		t.Fatalf("audit result = %#v requests = %#v", result, runner.requests)
	}
	if len(completion.requests) != 1 || completion.requests[0] != (goalplan.PlanCompletionRequest{TenantID: input.TenantID, ProjectID: input.ProjectID}) {
		t.Fatalf("completion requests = %#v", completion.requests)
	}
}

func TestModuleAuditActivityDoesNotPublishCompletionAfterAuditError(t *testing.T) {
	auditErr := errors.New("audit failed")
	runner := &moduleAuditRunnerStub{err: auditErr}
	completion := &planCompletionPublisherStub{}
	activity := &moduleAuditActivity{service: runner, completion: completion, local: true}

	_, err := activity.Run(context.Background(), aorworkflow.ExecutionInput{
		TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1",
	}, uuid.Must(uuid.NewV7()).String())
	if !errors.Is(err, auditErr) || len(completion.requests) != 0 {
		t.Fatalf("audit error = %v completion requests = %#v", err, completion.requests)
	}
}

func TestWorkerExecutionActivityBindsScopedServicePrincipal(t *testing.T) {
	runner := &executionRunnerStub{}
	payload, err := json.Marshal(executionActivityInput{Action: ExecutionActivityAction, ExecutionID: "execution_1"})
	if err != nil {
		t.Fatal(err)
	}
	activities, err := aorworkflow.NewActivities(workerActivityEffect{execution: runner})
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestActivityEnvironment()
	env.RegisterActivityWithOptions(activities.Execute, activity.RegisterOptions{Name: aorworkflow.ExecuteActivityName})
	input := aorworkflow.ExecutionInput{
		TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1", ActivityID: "activity_1", Payload: payload,
	}
	if _, err := env.ExecuteActivity(aorworkflow.ExecuteActivityName, input); err != nil {
		t.Fatal(err)
	}
	if !runner.hasPrincipal || runner.principal.ID != executionServicePrincipalID || runner.principal.Type != authn.PrincipalService || runner.principal.Role != authn.RoleService || runner.principal.TenantID != input.TenantID || runner.principal.ProjectID != input.ProjectID {
		t.Fatalf("execution principal = %#v, found=%v", runner.principal, runner.hasPrincipal)
	}
	if len(runner.requests) != 1 || runner.requests[0] != (execution.Request{ExecutionID: "execution_1", TenantID: input.TenantID, ProjectID: input.ProjectID, TaskID: input.TaskID}) {
		t.Fatalf("execution requests = %#v", runner.requests)
	}
}

func (provider *workerSandboxProvider) Create(_ context.Context, spec sandbox.SandboxSpec) (sandbox.SandboxHandle, error) {
	provider.created = true
	return sandbox.SandboxHandle{ID: spec.SandboxID}, nil
}

func (provider *workerSandboxProvider) Exec(_ context.Context, _ string, _ sandbox.ExecRequest) (sandbox.ExecResult, error) {
	return sandbox.ExecResult{ExitCode: 0, Stdout: []byte("ok"), StartedAt: time.Unix(1, 0), FinishedAt: time.Unix(2, 0)}, nil
}

func (provider *workerSandboxProvider) Export(context.Context, string, []string) ([]sandbox.ArtifactRef, error) {
	provider.exported = true
	return []sandbox.ArtifactRef{{Path: "result.json", URI: "artifact://sha256/0000000000000000000000000000000000000000000000000000000000000000", SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Size: 2}}, nil
}

func (provider *workerSandboxProvider) Snapshot(context.Context, string) (sandbox.SnapshotRef, error) {
	return sandbox.SnapshotRef{}, errors.New("unused")
}

func (provider *workerSandboxProvider) Terminate(context.Context, string, string) error { return nil }

func (provider *workerSandboxProvider) Destroy(_ context.Context, _ string) error {
	provider.destroyed = true
	return provider.destroyErr
}

func validWorkerSandboxSpec() sandbox.SandboxSpec {
	return sandbox.SandboxSpec{
		SandboxID:          "sandbox_1",
		TenantID:           "tenant_1",
		ProjectID:          "project_1",
		TaskID:             "task_1",
		Role:               sandbox.RoleExecutor,
		Platform:           sandbox.PlatformLinux,
		IsolationLevel:     sandbox.IsolationContainer,
		ImageDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		CPULimit:           "1",
		MemoryBytes:        1024,
		PIDsLimit:          32,
		DiskBytes:          1024,
		WallTimeSeconds:    30,
		NetworkPolicy:      sandbox.NetworkPolicy{Mode: "DENY_ALL"},
		AllowedExecutables: []string{"/bin/true"},
		WorkloadTrust:      sandbox.TrustTrusted,
		DeploymentProfile:  sandbox.ProfileLocal,
	}
}

func TestSandboxActivityEffectExecutesAndCleansUp(t *testing.T) {
	provider := &workerSandboxProvider{}
	authorizer := &workerSandboxAuthorizer{}
	payload, err := json.Marshal(sandboxActivityInput{Action: authz.ActionSandboxExec, Spec: validWorkerSandboxSpec(), Lease: authz.LeaseReference{ID: "lease_1", ExpiresAt: time.Now().Add(time.Hour), PolicyVersion: "sha256:0000000000000000000000000000000000000000000000000000000000000000", FencingToken: 1}, AgentInstanceID: "agent_1", BudgetAccountID: "budget_1", Executable: "/bin/true", TimeoutSeconds: 5, ExportPaths: []string{"result.json"}})
	if err != nil {
		t.Fatal(err)
	}
	activities, err := aorworkflow.NewActivities(sandboxActivityEffect{provider: provider, authorizer: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterWorkflowWithOptions(aorworkflow.ProjectExecutionWorkflow, temporalworkflow.RegisterOptions{Name: aorworkflow.ProjectExecutionWorkflowName})
	env.RegisterActivityWithOptions(activities.Execute, activity.RegisterOptions{Name: aorworkflow.ExecuteActivityName})
	env.ExecuteWorkflow(aorworkflow.ProjectExecutionWorkflowName, aorworkflow.ExecutionInput{TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1", ActivityID: "activity_1", Payload: payload})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	if !provider.created || !provider.destroyed || !provider.exported || authorizer.calls != 3 {
		t.Fatalf("sandbox lifecycle = created:%v destroyed:%v", provider.created, provider.destroyed)
	}
	var workflowOutput aorworkflow.ExecutionOutput
	if err := env.GetWorkflowResult(&workflowOutput); err != nil {
		t.Fatal(err)
	}
	output := workflowOutput.Output
	var decoded struct {
		Key      string `json:"idempotencyKey"`
		ExitCode int    `json:"exitCode"`
	}
	if err := json.Unmarshal(output, &decoded); err != nil || decoded.Key == "" || decoded.ExitCode != 0 {
		t.Fatalf("activity output = %s, err=%v", output, err)
	}
}

func TestSandboxActivityEffectRejectsUnknownFields(t *testing.T) {
	provider := &workerSandboxProvider{}
	_, err := (sandboxActivityEffect{provider: provider, authorizer: &workerSandboxAuthorizer{}}).Execute(context.Background(), "key", json.RawMessage(`{"action":"sandbox.exec","unknown":true}`))
	if !errors.Is(err, aorworkflow.ErrInvalidExecution) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestSandboxActivityEffectSurfacesDestroyFailure(t *testing.T) {
	provider := &workerSandboxProvider{destroyErr: errors.New("destroy failed")}
	input := sandboxActivityInput{Action: authz.ActionSandboxExec, Spec: validWorkerSandboxSpec(), Lease: authz.LeaseReference{ID: "lease_1", ExpiresAt: time.Now().Add(time.Hour), PolicyVersion: "sha256:0000000000000000000000000000000000000000000000000000000000000000", FencingToken: 1}, AgentInstanceID: "agent_1", BudgetAccountID: "budget_1", Executable: "/bin/true", TimeoutSeconds: 5}
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	execution := aorworkflow.ExecutionInput{TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1", ActivityID: "activity_1", Payload: payload}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestActivityEnvironment()
	activities, err := aorworkflow.NewActivities(sandboxActivityEffect{provider: provider, authorizer: &workerSandboxAuthorizer{}})
	if err != nil {
		t.Fatal(err)
	}
	env.RegisterActivityWithOptions(activities.Execute, activity.RegisterOptions{Name: aorworkflow.ExecuteActivityName})
	_, err = env.ExecuteActivity(aorworkflow.ExecuteActivityName, execution)
	if err == nil || !provider.destroyed {
		t.Fatalf("destroy failure = %v, destroyed=%v", err, provider.destroyed)
	}
}
