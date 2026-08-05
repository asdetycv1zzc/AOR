package toolbroker

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

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
	if err != nil || !task.moduleSpecAttached {
		return ExecutionScope{}, ErrLeaseInvalid
	}
	if err := tx.Commit(); err != nil {
		return ExecutionScope{}, ErrLeaseInvalid
	}
	return ExecutionScope{ProjectVersion: task.projectVersion, TaskVersion: task.scope.StateVersion, SpecDigest: task.scope.SpecDigest}, nil
}

func (resolver *PostgresScopeResolver) ResolveToolAuthorizationScope(ctx context.Context, query ToolAuthorizationScopeQuery) (ToolAuthorizationScope, error) {
	if resolver == nil || resolver.database == nil || query.BudgetAccountID == "" || query.Action == "" || !trustedRequestScope(ctx, query.TenantID, query.ProjectID) {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	tx, err := resolver.begin(ctx, query.TenantID)
	if err != nil {
		return ToolAuthorizationScope{}, ErrPolicyDenied
	}
	defer func() { _ = tx.Rollback() }()
	var project authz.ProjectScope
	var taskRecord postgresTaskScope
	if query.TaskID == "" {
		if authz.LeaseRoleRequiresTask(query.Role) {
			return ToolAuthorizationScope{}, ErrPolicyDenied
		}
		project, err = resolver.loadProject(ctx, tx, query.TenantID, query.ProjectID)
	} else {
		project, taskRecord, err = resolver.loadProjectTask(ctx, tx, query.TenantID, query.ProjectID, query.TaskID)
	}
	if err != nil || query.Role == authn.RolePlanSupervisor && !hasPlanSupervisorAuthority(ctx, tx, query) || query.Role == authn.RoleGlobalAuditor && !hasGlobalAuditorAuthority(ctx, tx, query) || query.Role == authn.RoleKnowledgeCurator && !hasKnowledgeCuratorAuthority(ctx, tx, query) || query.TaskID != "" && query.Role == authn.RoleModulePlanner && !hasPlanningAgentAuthority(ctx, tx, query) || query.TaskID != "" && !taskRecord.moduleSpecAttached && !allowsDetachedPlanningScope(query) {
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

func hasKnowledgeCuratorAuthority(ctx context.Context, tx *sql.Tx, query ToolAuthorizationScopeQuery) bool {
	if query.TaskID != "" || query.PrincipalID != query.ProjectID+":"+authn.RoleKnowledgeCurator {
		return false
	}
	var exists bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM agent_instances
  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3 AND role = 'KNOWLEDGE_CURATOR'
)`, query.TenantID, query.ProjectID, query.PrincipalID).Scan(&exists)
	return err == nil && exists
}

func hasGlobalAuditorAuthority(ctx context.Context, tx *sql.Tx, query ToolAuthorizationScopeQuery) bool {
	if query.TaskID != "" || query.PrincipalID == "" || !strings.HasPrefix(query.PrincipalID, query.ProjectID+":"+authn.RoleGlobalAuditor+":") {
		return false
	}
	var exists bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM agent_instances
  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3 AND role = 'GLOBAL_AUDITOR'
)`, query.TenantID, query.ProjectID, query.PrincipalID).Scan(&exists)
	return err == nil && exists
}

func allowsDetachedPlanningScope(query ToolAuthorizationScopeQuery) bool {
	return query.Action == authz.ActionModelGenerate && allowsPlanningAgentIdentity(query)
}

func hasPlanningAgentAuthority(ctx context.Context, tx *sql.Tx, query ToolAuthorizationScopeQuery) bool {
	if !allowsPlanningAgentIdentity(query) {
		return false
	}
	var exists bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM agent_instances
  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3 AND role = 'MODULE_PLANNER'
)`, query.TenantID, query.ProjectID, query.PrincipalID).Scan(&exists)
	return err == nil && exists
}

func hasPlanSupervisorAuthority(ctx context.Context, tx *sql.Tx, query ToolAuthorizationScopeQuery) bool {
	if !allowsPlanSupervisorIdentity(query) {
		return false
	}
	var exists bool
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM agent_instances
  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3 AND role = 'PLAN_SUPERVISOR'
)`, query.TenantID, query.ProjectID, query.PrincipalID).Scan(&exists)
	return err == nil && exists
}

func allowsPlanSupervisorIdentity(query ToolAuthorizationScopeQuery) bool {
	return query.Role == authn.RolePlanSupervisor && query.PrincipalID == query.ProjectID+":PLAN_SUPERVISOR"
}

func allowsPlanningAgentIdentity(query ToolAuthorizationScopeQuery) bool {
	return query.Role == authn.RoleModulePlanner && query.TaskID != "" &&
		query.PrincipalID == query.ProjectID+":MODULE_PLANNER:"+query.TaskID
}

type postgresTaskScope struct {
	projectVersion     int64
	moduleSpecAttached bool
	scope              authz.TaskScope
}

func (resolver *PostgresScopeResolver) loadProject(ctx context.Context, tx *sql.Tx, tenantID, projectID string) (authz.ProjectScope, error) {
	project := authz.ProjectScope{TenantID: tenantID, ID: projectID}
	err := tx.QueryRowContext(ctx, `
SELECT state, state_version, data_classification
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, projectID).Scan(
		&project.State, &project.StateVersion, &project.Classification,
	)
	if err != nil {
		return authz.ProjectScope{}, err
	}
	return project, nil
}

func (resolver *PostgresScopeResolver) loadProjectTask(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID string) (authz.ProjectScope, postgresTaskScope, error) {
	var project authz.ProjectScope
	var task authz.TaskScope
	var scopeJSON []byte
	var moduleSpecAttached bool
	var platform, sandboxLevel, planStatus string
	err := tx.QueryRowContext(ctx, `
SELECT p.state, p.state_version, p.data_classification,
	       t.state, t.state_version, COALESCE(ms.content_sha256, plan.content_sha256),
	       COALESCE(ms.execution_platform, planned.content_jsonb->>'executionPlatform'),
	       COALESCE(ms.isolation_level, planned.content_jsonb->>'sandboxLevel'),
	       COALESCE(ms.content_jsonb, planned.content_jsonb), t.module_spec_id IS NOT NULL,
	       plan.status
FROM projects p
JOIN module_tasks t ON t.tenant_id = p.tenant_id AND t.project_id = p.id
LEFT JOIN module_specs ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
JOIN plan_specs plan ON plan.tenant_id = t.tenant_id AND plan.id = COALESCE(t.planning_spec_id, ms.plan_spec_id)
JOIN LATERAL (
	  SELECT module AS content_jsonb
	  FROM jsonb_array_elements(plan.content_jsonb->'modules') AS module
	  WHERE module->>'moduleId' = COALESCE(t.module_id, ms.module_id)
) AS planned ON true
WHERE p.tenant_id = $1::uuid AND p.id = $2::uuid AND t.id = $3::uuid`, tenantID, projectID, taskID).Scan(
		&project.State, &project.StateVersion, &project.Classification,
		&task.State, &task.StateVersion, &task.SpecDigest, &platform,
		&sandboxLevel, &scopeJSON, &moduleSpecAttached, &planStatus,
	)
	if err != nil {
		return authz.ProjectScope{}, postgresTaskScope{}, err
	}
	project.TenantID, project.ID = tenantID, projectID
	task.TenantID, task.ProjectID, task.ID = tenantID, projectID, taskID
	task.DeploymentProfile = resolver.deploymentProfile
	if moduleSpecAttached {
		var module contracts.ModuleSpec
		if json.Unmarshal(scopeJSON, &module) != nil || module.ProjectID != projectID || string(module.ExecutionPlatform) != platform || string(module.SandboxLevel) != sandboxLevel || len(module.AllowedPaths) > 256 {
			return authz.ProjectScope{}, postgresTaskScope{}, ErrPolicyDenied
		}
		task.ExecutionPlatform, task.SandboxLevel = platform, sandboxLevel
		task.OwnedPaths = append([]string(nil), module.AllowedPaths...)
		task.WorkloadTrust = string(module.WorkloadProfile.Trust)
		task.HostileMultiTenant = module.WorkloadProfile.HostileMultiTenant
		task.RequiresNetworkIsolation = module.WorkloadProfile.RequiresNetworkIsolation
		task.RequiresHiddenConfidentiality = module.WorkloadProfile.RequiresHiddenTestConfidentiality
	} else {
		var module contracts.PlanModule
		if json.Unmarshal(scopeJSON, &module) != nil || module.ModuleID == "" || string(module.ExecutionPlatform) != platform || string(module.SandboxLevel) != sandboxLevel || len(module.OwnedPaths) > 256 || planStatus != "DRAFT" || task.State != "QUEUED_PLANNING" && task.State != "PLANNING" {
			return authz.ProjectScope{}, postgresTaskScope{}, ErrPolicyDenied
		}
	}
	return project, postgresTaskScope{projectVersion: project.StateVersion, moduleSpecAttached: moduleSpecAttached, scope: task}, nil
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
