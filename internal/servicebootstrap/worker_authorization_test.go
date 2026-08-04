package servicebootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type staticSandboxScopeResolver struct {
	scope sandboxExecutionScope
	err   error
}

func (resolver staticSandboxScopeResolver) Resolve(context.Context, string, string, string, string) (sandboxExecutionScope, error) {
	return resolver.scope, resolver.err
}

type recordingSandboxLeaseValidator struct {
	check authz.LeaseCheck
	lease authz.CapabilityLease
	err   error
}

func (validator *recordingSandboxLeaseValidator) Validate(_ context.Context, check authz.LeaseCheck) (authz.CapabilityLease, error) {
	validator.check = check
	return validator.lease, validator.err
}

func TestLeaseBoundSandboxAuthorizerUsesCurrentScopeAndExactParameters(t *testing.T) {
	input, execution, scope := validSandboxAuthorizationFixture()
	validator := &recordingSandboxLeaseValidator{lease: authz.CapabilityLease{ExpiresAt: input.Lease.ExpiresAt, BudgetAccountID: input.BudgetAccountID, FencingToken: input.Lease.FencingToken}}
	authorizer, err := newLeaseBoundSandboxAuthorizer(runtimeconfig.Config{DeploymentProfile: "TEST", Sandbox: runtimeconfig.SandboxConfig{ImageReference: "golang@sha256:0000000000000000000000000000000000000000000000000000000000000000"}}, staticSandboxScopeResolver{scope: scope}, validator)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(context.Background(), execution, input); err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := sandboxExecutionParameterDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	if validator.check.Action != authz.ActionSandboxExec || validator.check.ParameterDigest != expectedDigest || validator.check.ProjectVersion != scope.ProjectVersion || validator.check.TaskVersion != scope.TaskVersion || validator.check.SpecDigest != scope.ModuleDigest || validator.check.FencingToken != scope.LatestFencingToken {
		t.Fatalf("lease check = %#v", validator.check)
	}
}

func TestLeaseBoundSandboxAuthorizerRejectsPolicyAndLeaseDrift(t *testing.T) {
	input, execution, scope := validSandboxAuthorizationFixture()
	validator := &recordingSandboxLeaseValidator{lease: authz.CapabilityLease{ExpiresAt: input.Lease.ExpiresAt, BudgetAccountID: input.BudgetAccountID, FencingToken: input.Lease.FencingToken}}

	changed := input
	changed.Spec.NetworkPolicy = sandbox.NetworkPolicy{Mode: "ALLOWLIST", Destinations: []string{"https://example.test"}}
	authorizer, err := newLeaseBoundSandboxAuthorizer(runtimeconfig.Config{DeploymentProfile: "TEST", Sandbox: runtimeconfig.SandboxConfig{ImageReference: "golang@sha256:0000000000000000000000000000000000000000000000000000000000000000"}}, staticSandboxScopeResolver{scope: scope}, validator)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(context.Background(), execution, changed); err == nil {
		t.Fatal("module network policy drift was authorized")
	}

	validator.err = aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	if err := authorizer.Authorize(context.Background(), execution, input); !errors.Is(err, validator.err) {
		t.Fatalf("revoked lease error = %v", err)
	}

	validator.err = nil
	validator.lease.ExpiresAt = input.Lease.ExpiresAt.Add(time.Second)
	if err := authorizer.Authorize(context.Background(), execution, input); err == nil {
		t.Fatal("lease expiry drift was authorized")
	}
}

func validSandboxAuthorizationFixture() (sandboxActivityInput, aorworkflow.ExecutionInput, sandboxExecutionScope) {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	expiresAt := time.Date(2030, 1, 1, 0, 5, 0, 0, time.UTC)
	spec := validWorkerSandboxSpec()
	module := contracts.ModuleSpec{
		ModuleSpecVersion: 1,
		ModuleID:          "module_1",
		ProjectID:         spec.ProjectID,
		PlanVersion:       1,
		ExecutionPlatform: contracts.PlatformLinux,
		SandboxLevel:      contracts.IsolationContainer,
		NetworkPolicy:     contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll},
		WorkloadProfile:   contracts.WorkloadProfile{Trust: contracts.WorkloadTrusted},
		SHA256:            digest,
	}
	input := sandboxActivityInput{
		Action:          authz.ActionSandboxExec,
		Spec:            spec,
		Lease:           authz.LeaseReference{ID: "lease_1", ExpiresAt: expiresAt, PolicyVersion: digest, FencingToken: 3},
		AgentInstanceID: "agent_1",
		BudgetAccountID: "budget_1",
		Executable:      "/bin/true",
		Arguments:       []string{"--version"},
		TimeoutSeconds:  5,
		ExportPaths:     []string{"result.json"},
	}
	execution := aorworkflow.ExecutionInput{TenantID: spec.TenantID, ProjectID: spec.ProjectID, TaskID: spec.TaskID, ActivityID: "activity_1"}
	scope := sandboxExecutionScope{ProjectState: string(contracts.ProjectExecuting), ProjectVersion: 7, TaskState: string(contracts.TaskExecuting), TaskVersion: 9, LatestFencingToken: 3, BudgetAvailable: true, ModuleDigest: digest, Module: module}
	return input, execution, scope
}
