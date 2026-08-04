package toolbroker

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/contracts"
)

type PostgresScopeResolverConfig struct {
	Database          *sql.DB
	DeploymentProfile string
}

// PostgresScopeResolver rehydrates every mutable authorization fact under a
// tenant-scoped, read-only transaction. Request metadata supplies identifiers
// only; project, task, budget, module, and approval state comes from Postgres.
type PostgresScopeResolver struct {
	database          *sql.DB
	deploymentProfile string
}

func NewPostgresScopeResolver(config PostgresScopeResolverConfig) (*PostgresScopeResolver, error) {
	if config.Database == nil || !validDeploymentProfile(config.DeploymentProfile) {
		return nil, ErrMCPConfig
	}
	return &PostgresScopeResolver{database: config.Database, deploymentProfile: config.DeploymentProfile}, nil
}

func (resolver *PostgresScopeResolver) ResolveExecutionScope(ctx context.Context, tenantID, projectID, taskID string) (ExecutionScope, error) {
	if resolver == nil || resolver.database == nil || !trustedRequestScope(ctx, tenantID, projectID) {
		return ExecutionScope{}, ErrLeaseInvalid
	}
	tx, err := resolver.begin(ctx, tenantID)
	if err != nil {
		return ExecutionScope{}, ErrLeaseInvalid
	}
	defer func() { _ = tx.Rollback() }()
	_, task, err := resolver.loadProjectTask(ctx, tx, tenantID, projectID, taskID)
	if err != nil {
		return ExecutionScope{}, ErrLeaseInvalid
	}
	if err := tx.Commit(); err != nil {
		return ExecutionScope{}, ErrLeaseInvalid
	}
	return ExecutionScope{ProjectVersion: task.projectVersion, TaskVersion: task.scope.StateVersion, SpecDigest: task.scope.SpecDigest}, nil
}

func (resolver *PostgresScopeResolver) ResolveToolAuthorizationScope(ctx context.Context, query ToolAuthorizationScopeQuery) (ToolAuthorizationScope, error) {
	if resolver == nil || resolver.database == nil || query.BudgetAccountID == "" || !trustedRequestScope(ctx, query.TenantID, query.ProjectID) {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	tx, err := resolver.begin(ctx, query.TenantID)
	if err != nil {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	defer func() { _ = tx.Rollback() }()
	project, taskRecord, err := resolver.loadProjectTask(ctx, tx, query.TenantID, query.ProjectID, query.TaskID)
	if err != nil {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	budget, err := loadToolBudget(ctx, tx, query)
	if err != nil {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	approval, err := loadToolApproval(ctx, tx, query)
	if err != nil {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	if err := tx.Commit(); err != nil {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	return ToolAuthorizationScope{Project: project, Task: taskRecord.scope, Budget: budget, Approval: approval}, nil
}

type postgresTaskScope struct {
	projectVersion int64
	scope          authz.TaskScope
}

func (resolver *PostgresScopeResolver) loadProjectTask(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID string) (authz.ProjectScope, postgresTaskScope, error) {
	var project authz.ProjectScope
	var task authz.TaskScope
	var moduleJSON []byte
	var platform, sandboxLevel string
	err := tx.QueryRowContext(ctx, `
SELECT p.state, p.state_version, p.data_classification,
       t.state, t.state_version, ms.content_sha256, ms.execution_platform,
       ms.isolation_level, ms.content_jsonb
FROM projects p
JOIN module_tasks t ON t.tenant_id = p.tenant_id AND t.project_id = p.id
JOIN module_specs ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
WHERE p.tenant_id = $1::uuid AND p.id = $2::uuid AND t.id = $3::uuid`, tenantID, projectID, taskID).Scan(
		&project.State, &project.StateVersion, &project.Classification,
		&task.State, &task.StateVersion, &task.SpecDigest, &platform,
		&sandboxLevel, &moduleJSON,
	)
	if err != nil {
		return authz.ProjectScope{}, postgresTaskScope{}, err
	}
	var module contracts.ModuleSpec
	if json.Unmarshal(moduleJSON, &module) != nil || module.ProjectID != projectID || string(module.ExecutionPlatform) != platform || string(module.SandboxLevel) != sandboxLevel || len(module.AllowedPaths) > 256 {
		return authz.ProjectScope{}, postgresTaskScope{}, ErrPolicyDenied
	}
	project.TenantID, project.ID = tenantID, projectID
	task.TenantID, task.ProjectID, task.ID = tenantID, projectID, taskID
	task.OwnedPaths = append([]string(nil), module.AllowedPaths...)
	task.ExecutionPlatform, task.SandboxLevel = platform, sandboxLevel
	task.WorkloadTrust = string(module.WorkloadProfile.Trust)
	task.DeploymentProfile = resolver.deploymentProfile
	task.HostileMultiTenant = module.WorkloadProfile.HostileMultiTenant
	task.RequiresNetworkIsolation = module.WorkloadProfile.RequiresNetworkIsolation
	task.RequiresHiddenConfidentiality = module.WorkloadProfile.RequiresHiddenTestConfidentiality
	return project, postgresTaskScope{projectVersion: project.StateVersion, scope: task}, nil
}

func loadToolBudget(ctx context.Context, tx *sql.Tx, query ToolAuthorizationScopeQuery) (authz.BudgetScope, error) {
	var scopeType, scopeID string
	var available bool
	err := tx.QueryRowContext(ctx, `
SELECT scope_type, scope_id,
       hard_limit_micros >= spent_micros + reserved_micros
       AND hard_limit_micros - spent_micros - reserved_micros > 0
       AND period_start <= transaction_timestamp()
       AND (period_end IS NULL OR transaction_timestamp() < period_end)
FROM budget_accounts
WHERE tenant_id = $1::uuid AND id = $2`, query.TenantID, query.BudgetAccountID).Scan(&scopeType, &scopeID, &available)
	if err != nil {
		return authz.BudgetScope{}, err
	}
	if !toolBudgetScopeMatches(scopeType, scopeID, query) {
		available = false
	}
	return authz.BudgetScope{AccountID: query.BudgetAccountID, Available: available}, nil
}

func toolBudgetScopeMatches(scopeType, scopeID string, query ToolAuthorizationScopeQuery) bool {
	switch scopeType {
	case "PROJECT":
		return scopeID == query.ProjectID
	case "TASK":
		return scopeID == query.TaskID
	case "AGENT":
		return scopeID == query.PrincipalID
	case "ROLE":
		return scopeID == query.Role
	default:
		return false
	}
}

func loadToolApproval(ctx context.Context, tx *sql.Tx, query ToolAuthorizationScopeQuery) (*authz.Approval, error) {
	if query.ApprovalID == "" {
		return nil, nil
	}
	approval := &authz.Approval{ID: query.ApprovalID}
	var constraints []byte
	var expiresAt, revokedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, principal_id, subject_type, subject_id,
       subject_version, subject_sha256, constraints_jsonb, issued_at, expires_at,
       revoked_at, signature
FROM approvals
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid`, query.TenantID, query.ProjectID, query.ApprovalID).Scan(
		&approval.TenantID, &approval.ProjectID, &approval.PrincipalID,
		&approval.SubjectType, &approval.SubjectID, &approval.SubjectVersion,
		&approval.SubjectDigest, &constraints, &approval.IssuedAt, &expiresAt,
		&revokedAt, &approval.Signature,
	)
	if err != nil {
		return nil, err
	}
	var parsedConstraints struct {
		CoApproverID string `json:"coApproverId"`
	}
	if json.Unmarshal(constraints, &parsedConstraints) != nil {
		return nil, ErrPolicyDenied
	}
	approval.CoApproverID = parsedConstraints.CoApproverID
	approval.IssuedAt = approval.IssuedAt.UTC()
	if expiresAt.Valid {
		approval.ExpiresAt = expiresAt.Time.UTC()
	}
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		approval.RevokedAt = &value
	}
	return approval, nil
}

func (resolver *PostgresScopeResolver) begin(ctx context.Context, tenantID string) (*sql.Tx, error) {
	if ctx == nil || tenantID == "" {
		return nil, ErrPolicyDenied
	}
	tx, err := resolver.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		_ = tx.Rollback()
		return nil, ErrPolicyDenied
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func trustedRequestScope(ctx context.Context, tenantID, projectID string) bool {
	if ctx == nil || tenantID == "" || projectID == "" {
		return false
	}
	principal, ok := authn.PrincipalFromContext(ctx)
	return ok && principal.TenantID == tenantID && (principal.ProjectID == "" || principal.ProjectID == projectID)
}

func validDeploymentProfile(value string) bool {
	switch value {
	case "LOCAL", "TEST", "PREPRODUCTION", "PRODUCTION":
		return true
	default:
		return false
	}
}

var _ ExecutionScopeResolver = (*PostgresScopeResolver)(nil)
var _ ToolAuthorizationScopeResolver = (*PostgresScopeResolver)(nil)
