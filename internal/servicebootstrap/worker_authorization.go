package servicebootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type sandboxExecutionScope struct {
	ProjectState       string
	ProjectVersion     int64
	TaskState          string
	TaskVersion        int64
	LatestFencingToken int64
	BudgetAvailable    bool
	ModuleDigest       string
	Module             contracts.ModuleSpec
}

type sandboxExecutionScopeResolver interface {
	Resolve(context.Context, string, string, string, string) (sandboxExecutionScope, error)
}

type sandboxLeaseValidator interface {
	Validate(context.Context, authz.LeaseCheck) (authz.CapabilityLease, error)
}

type sandboxExecutionAuthorizer interface {
	Authorize(context.Context, aorworkflow.ExecutionInput, sandboxActivityInput) error
}

type leaseBoundSandboxAuthorizer struct {
	scopes            sandboxExecutionScopeResolver
	leases            sandboxLeaseValidator
	imageDigest       string
	deploymentProfile sandbox.DeploymentProfile
}

func newLeaseBoundSandboxAuthorizer(config runtimeconfig.Config, scopes sandboxExecutionScopeResolver, leases sandboxLeaseValidator) (*leaseBoundSandboxAuthorizer, error) {
	if scopes == nil || leases == nil {
		return nil, ErrWorkerConfiguration
	}
	profile := sandbox.ProfileLocal
	if config.DeploymentProfile == "PREPRODUCTION" || config.DeploymentProfile == "PRODUCTION" {
		profile = sandbox.ProfileProduction
	}
	digest := configuredImageDigest(config.Sandbox.ImageReference)
	if config.Sandbox.ImageReference != "" && digest == "" {
		return nil, ErrWorkerConfiguration
	}
	return &leaseBoundSandboxAuthorizer{scopes: scopes, leases: leases, imageDigest: digest, deploymentProfile: profile}, nil
}

func (authorizer *leaseBoundSandboxAuthorizer) Authorize(ctx context.Context, execution aorworkflow.ExecutionInput, input sandboxActivityInput) error {
	if authorizer == nil || authorizer.scopes == nil || authorizer.leases == nil || ctx == nil {
		return ErrWorkerUnavailable
	}
	scope, err := authorizer.scopes.Resolve(ctx, execution.TenantID, execution.ProjectID, execution.TaskID, input.BudgetAccountID)
	if err != nil {
		return err
	}
	if err := validateSandboxExecutionScope(scope, authorizer.imageDigest, authorizer.deploymentProfile, input); err != nil {
		return err
	}
	parameterDigest, err := sandboxExecutionParameterDigest(input)
	if err != nil {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "sandbox parameters"})
	}
	resource := authz.Resource{Type: "sandbox", ID: input.Spec.SandboxID}
	lease, err := authorizer.leases.Validate(ctx, authz.LeaseCheck{
		LeaseID:         input.Lease.ID,
		AgentInstanceID: input.AgentInstanceID,
		PrincipalID:     input.AgentInstanceID,
		PrincipalType:   authn.PrincipalAgentInstance,
		TenantID:        execution.TenantID,
		ProjectID:       execution.ProjectID,
		ProjectVersion:  scope.ProjectVersion,
		TaskID:          execution.TaskID,
		TaskVersion:     scope.TaskVersion,
		SpecDigest:      scope.ModuleDigest,
		Role:            string(input.Spec.Role),
		Action:          authz.ActionSandboxExec,
		Resource:        resource,
		ParameterDigest: parameterDigest,
		PolicyVersion:   input.Lease.PolicyVersion,
		BudgetAccountID: input.BudgetAccountID,
		Capability:      authz.ActionSandboxExec,
		FencingToken:    input.Lease.FencingToken,
	})
	if err != nil {
		return err
	}
	if !lease.ExpiresAt.Equal(input.Lease.ExpiresAt) || lease.BudgetAccountID != input.BudgetAccountID || scope.LatestFencingToken != lease.FencingToken {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "sandbox lease binding"})
	}
	return nil
}

func validateSandboxExecutionScope(scope sandboxExecutionScope, imageDigest string, profile sandbox.DeploymentProfile, input sandboxActivityInput) error {
	module := scope.Module
	expectedTrustedSingleTenant := module.ExecutionPlatform == contracts.PlatformWindows && module.WorkloadProfile.Trust == contracts.WorkloadTrusted && !module.WorkloadProfile.HostileMultiTenant
	if module.Validate() != nil || module.SHA256 != scope.ModuleDigest || module.ProjectID != input.Spec.ProjectID || string(module.ExecutionPlatform) != string(input.Spec.Platform) || string(module.SandboxLevel) != string(input.Spec.IsolationLevel) || string(module.WorkloadProfile.Trust) != string(input.Spec.WorkloadTrust) || module.WorkloadProfile.RequiresHiddenTestConfidentiality != input.Spec.RequiresHiddenTests || module.WorkloadProfile.RequiresNetworkIsolation != input.Spec.RequiresNetworkIsolation || module.WorkloadProfile.HostileMultiTenant != input.Spec.HostileMultiTenant || string(module.NetworkPolicy.Mode) != input.Spec.NetworkPolicy.Mode || !slices.Equal(module.NetworkPolicy.Destinations, input.Spec.NetworkPolicy.Destinations) || input.Spec.DeploymentProfile != profile || input.Spec.TrustedSingleTenant != expectedTrustedSingleTenant || input.Spec.RiskAcceptanceApprovalID != "" || scope.LatestFencingToken != input.Lease.FencingToken || !scope.BudgetAvailable {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "authoritative sandbox specification"})
	}
	if input.Spec.Platform == sandbox.PlatformLinux && input.Spec.ImageDigest != imageDigest || input.Spec.Platform == sandbox.PlatformWindows && input.Spec.ImageDigest != "" {
		return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "sandbox image"})
	}
	validState := input.Spec.Role == sandbox.RoleExecutor && scope.ProjectState == string(contracts.ProjectExecuting) && scope.TaskState == string(contracts.TaskExecuting)
	validState = validState || input.Spec.Role == sandbox.RoleAuditor && (scope.ProjectState == string(contracts.ProjectExecuting) || scope.ProjectState == string(contracts.ProjectGlobalAudit)) && (scope.TaskState == string(contracts.TaskDeterministicAudit) || scope.TaskState == string(contracts.TaskLLMAudit))
	if !validState {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "sandbox task state"})
	}
	return nil
}

func sandboxExecutionParameterDigest(input sandboxActivityInput) (string, error) {
	encoded, err := json.Marshal(struct {
		Action         string              `json:"action"`
		Spec           sandbox.SandboxSpec `json:"spec"`
		Executable     string              `json:"executable"`
		Arguments      []string            `json:"arguments,omitempty"`
		WorkingDir     string              `json:"workingDir,omitempty"`
		TimeoutSeconds int                 `json:"timeoutSeconds"`
		ExportPaths    []string            `json:"exportPaths,omitempty"`
	}{input.Action, input.Spec, input.Executable, input.Arguments, input.WorkingDir, input.TimeoutSeconds, input.ExportPaths})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func configuredImageDigest(reference string) string {
	const marker = "@sha256:"
	index := strings.LastIndex(reference, marker)
	if index < 0 || index+len(marker)+64 != len(reference) {
		return ""
	}
	return reference[index+1:]
}

type postgresSandboxExecutionScopeResolver struct {
	database *sql.DB
}

func newPostgresSandboxExecutionScopeResolver(database *sql.DB) (*postgresSandboxExecutionScopeResolver, error) {
	if database == nil {
		return nil, ErrWorkerConfiguration
	}
	return &postgresSandboxExecutionScopeResolver{database: database}, nil
}

func (resolver *postgresSandboxExecutionScopeResolver) Resolve(ctx context.Context, tenantID, projectID, taskID, budgetAccountID string) (sandboxExecutionScope, error) {
	if resolver == nil || resolver.database == nil || ctx == nil || tenantID == "" || projectID == "" || taskID == "" || budgetAccountID == "" {
		return sandboxExecutionScope{}, aorerrors.New(aorerrors.CodePolicyDenied, "", nil)
	}
	tx, err := resolver.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return sandboxExecutionScope{}, errors.Join(ErrWorkerUnavailable, err)
	}
	defer func() { _ = tx.Rollback() }()
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		return sandboxExecutionScope{}, errors.Join(ErrWorkerUnavailable, err)
	}
	if superuser || bypassRLS {
		return sandboxExecutionScope{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "database role bypasses tenant isolation"})
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return sandboxExecutionScope{}, errors.Join(ErrWorkerUnavailable, err)
	}
	var scope sandboxExecutionScope
	var moduleJSON []byte
	var moduleVersion int
	var platform, isolation string
	err = tx.QueryRowContext(ctx, `
SELECT p.state, p.state_version, t.state, t.state_version, t.latest_fencing_token,
       ms.version, ms.content_sha256, ms.execution_platform, ms.isolation_level,
	       ms.content_jsonb,
	       b.hard_limit_micros >= b.spent_micros + b.reserved_micros
	       AND b.hard_limit_micros - b.spent_micros - b.reserved_micros > 0
	       AND b.period_start <= transaction_timestamp()
	       AND (b.period_end IS NULL OR transaction_timestamp() < b.period_end)
FROM projects p
JOIN module_tasks t ON t.tenant_id = p.tenant_id AND t.project_id = p.id
JOIN module_specs ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
JOIN plan_specs ps ON ps.tenant_id = ms.tenant_id AND ps.id = ms.plan_spec_id
JOIN budget_accounts b ON b.tenant_id = p.tenant_id AND b.id = $4
	AND ((b.scope_type = 'PROJECT' AND b.scope_id = p.id::text)
	  OR (b.scope_type = 'TASK' AND b.scope_id = t.id::text))
WHERE p.tenant_id = $1::uuid AND p.id = $2::uuid AND t.id = $3::uuid
	  AND p.active_plan_spec_id = ps.id AND ps.status = 'PUBLISHED'`, tenantID, projectID, taskID, budgetAccountID).Scan(
		&scope.ProjectState, &scope.ProjectVersion, &scope.TaskState, &scope.TaskVersion,
		&scope.LatestFencingToken, &moduleVersion, &scope.ModuleDigest, &platform,
		&isolation, &moduleJSON, &scope.BudgetAvailable,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sandboxExecutionScope{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "sandbox execution scope"})
	}
	if err != nil {
		return sandboxExecutionScope{}, errors.Join(ErrWorkerUnavailable, err)
	}
	if json.Unmarshal(moduleJSON, &scope.Module) != nil || scope.Module.ModuleSpecVersion != moduleVersion || scope.Module.SHA256 != scope.ModuleDigest || string(scope.Module.ExecutionPlatform) != platform || string(scope.Module.SandboxLevel) != isolation {
		return sandboxExecutionScope{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "module specification"})
	}
	if err := tx.Commit(); err != nil {
		return sandboxExecutionScope{}, errors.Join(ErrWorkerUnavailable, err)
	}
	return scope, nil
}
