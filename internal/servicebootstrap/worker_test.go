package servicebootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	temporalworkflow "go.temporal.io/sdk/workflow"
)

type workerSandboxProvider struct {
	created   bool
	destroyed bool
}

func TestLinuxExecutionProviderRequiresPinnedDedicatedEngine(t *testing.T) {
	_, err := newExecutionProvider(runtimeconfig.Config{Sandbox: runtimeconfig.SandboxConfig{
		RuntimeName:     "runc",
		SeccompProfile:  "builtin",
		MandatoryPolicy: "apparmor=aor-sandbox",
		HoldCommand:     []string{"/bin/sh"},
	}})
	if !errors.Is(err, ErrWorkerConfiguration) && !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("missing Linux engine configuration error = %v", err)
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
	return nil, errors.New("unused")
}

func (provider *workerSandboxProvider) Snapshot(context.Context, string) (sandbox.SnapshotRef, error) {
	return sandbox.SnapshotRef{}, errors.New("unused")
}

func (provider *workerSandboxProvider) Terminate(context.Context, string, string) error { return nil }

func (provider *workerSandboxProvider) Destroy(_ context.Context, _ string) error {
	provider.destroyed = true
	return nil
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
	payload, err := json.Marshal(sandboxActivityInput{Action: "sandbox.exec", Spec: validWorkerSandboxSpec(), Executable: "/bin/true", TimeoutSeconds: 5})
	if err != nil {
		t.Fatal(err)
	}
	activities, err := aorworkflow.NewActivities(sandboxActivityEffect{provider: provider})
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
	if !provider.created || !provider.destroyed {
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
	_, err := (sandboxActivityEffect{provider: provider}).Execute(context.Background(), "key", json.RawMessage(`{"action":"sandbox.exec","unknown":true}`))
	if !errors.Is(err, aorworkflow.ErrInvalidExecution) {
		t.Fatalf("unknown field error = %v", err)
	}
}
