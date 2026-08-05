package execution

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/prompts"
	"github.com/google/uuid"
)

type PostgresAssignmentAuthority struct {
	database *sql.DB
}

type RuntimeBindingRequest struct {
	ExecutionID     string
	TenantID        string
	ProjectID       string
	TaskID          string
	AttemptSeriesID string
	AgentInstanceID string
	FencingToken    int64
	LeaseID         string
	Provider        string
	Model           string
	PromptVersion   string
}

func NewPostgresAssignmentAuthority(database *sql.DB) (*PostgresAssignmentAuthority, error) {
	if database == nil {
		return nil, ErrExecutionUnavailable
	}
	return &PostgresAssignmentAuthority{database: database}, nil
}

func (authority *PostgresAssignmentAuthority) Assign(ctx context.Context, request AssignmentRequest) (Assignment, error) {
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil || !validAssignmentRequest(request) {
		return Assignment{}, ErrInvalidRequest
	}
	tx, err := authority.begin(ctx, request.Project.TenantID, false)
	if err != nil {
		return Assignment{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var projectState, taskState, moduleID, attemptSeriesID, specDigest string
	var projectVersion, taskVersion, fencingToken int64
	var attempt, specVersion int
	err = tx.QueryRowContext(ctx, `
SELECT p.state, p.state_version, t.state, t.state_version,
       COALESCE(t.module_id, ms.module_id),
       COALESCE(t.active_attempt_series_id::text, ''), t.attempt_count,
       t.latest_fencing_token, ms.version, ms.content_sha256
FROM projects AS p
JOIN module_tasks AS t
  ON t.tenant_id = p.tenant_id AND t.project_id = p.id
JOIN module_specs AS ms
  ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
WHERE p.tenant_id = $1::uuid AND p.id = $2::uuid AND t.id = $3::uuid
FOR UPDATE OF t`, request.Project.TenantID, request.Project.ID, request.Task.ID).Scan(
		&projectState, &projectVersion, &taskState, &taskVersion,
		&moduleID, &attemptSeriesID, &attempt, &fencingToken, &specVersion, &specDigest,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Assignment{}, ErrAssignmentInvalid
	}
	if err != nil {
		return Assignment{}, err
	}
	if projectState != string(contracts.ProjectExecuting) || projectVersion != request.Project.Version ||
		taskState != string(request.Task.State) || taskVersion != request.Task.Version || moduleID != request.ModuleSpec.ModuleID ||
		attemptSeriesID != request.Task.AttemptSeriesID || attempt != request.Task.Attempt || fencingToken != request.Task.FencingToken ||
		specVersion != request.ModuleSpec.ModuleSpecVersion || specDigest != request.ModuleSpec.SHA256 {
		return Assignment{}, ErrAssignmentInvalid
	}
	targetFence := fencingToken
	if request.Task.State == contracts.TaskReadyExecution {
		targetFence++
	}
	if targetFence < 1 {
		return Assignment{}, ErrAssignmentInvalid
	}
	fenceValue := strconv.FormatInt(targetFence, 10)
	agentID := stableAssignmentID("agt_executor_", request.Project.TenantID, request.Project.ID, request.Task.ID, attemptSeriesID, fenceValue)
	sandboxID := stableAssignmentID("sbx_executor_", request.Project.TenantID, request.Project.ID, request.Task.ID, attemptSeriesID, fenceValue)

	if _, err := tx.ExecContext(ctx, `
INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
VALUES ($1, $2::uuid, $3::uuid, 'EXECUTOR', 'UNASSIGNED', 'UNASSIGNED',
        'UNASSIGNED', $4, 'DECLARED', transaction_timestamp())
ON CONFLICT (id) DO NOTHING`, agentID, request.Project.TenantID, request.Project.ID, prompts.BaselineVersion); err != nil {
		return Assignment{}, err
	}
	var storedTenant, storedProject, storedRole, storedPrompt, storedState string
	err = tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, role, prompt_bundle_version, state
FROM agent_instances
WHERE tenant_id = $1::uuid AND id = $2
FOR UPDATE`, request.Project.TenantID, agentID).Scan(&storedTenant, &storedProject, &storedRole, &storedPrompt, &storedState)
	if err != nil {
		return Assignment{}, err
	}
	if storedTenant != request.Project.TenantID || storedProject != request.Project.ID || storedRole != string(agentruntime.RoleExecutor) || storedPrompt != prompts.BaselineVersion || storedState != "DECLARED" && storedState != "LEASED" {
		return Assignment{}, ErrAssignmentInvalid
	}

	assignmentID, err := uuid.NewV7()
	if err != nil {
		return Assignment{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO execution_assignments
  (id, tenant_id, project_id, module_task_id, module_spec_id, attempt_series_id,
   execution_id, agent_instance_id, sandbox_id, fencing_token)
SELECT $1::uuid, $2::uuid, $3::uuid, t.id, t.module_spec_id,
       t.active_attempt_series_id, $5, $6, $7, $8
FROM module_tasks AS t
WHERE t.tenant_id = $2::uuid AND t.project_id = $3::uuid AND t.id = $4::uuid
ON CONFLICT DO NOTHING`, assignmentID.String(), request.Project.TenantID, request.Project.ID,
		request.Task.ID, request.ExecutionID, agentID, sandboxID, targetFence); err != nil {
		return Assignment{}, err
	}
	var storedExecution, storedAgent, storedSandbox, storedProjectID, storedTaskID, storedSeriesID, storedModuleID string
	var storedFence int64
	err = tx.QueryRowContext(ctx, `
SELECT execution_id, agent_instance_id, sandbox_id, project_id::text,
       module_task_id::text, attempt_series_id::text, module_spec_id::text,
       fencing_token
FROM execution_assignments
WHERE tenant_id = $1::uuid AND module_task_id = $2::uuid
  AND attempt_series_id = $3::uuid AND fencing_token = $4
FOR UPDATE`, request.Project.TenantID, request.Task.ID, attemptSeriesID, targetFence).Scan(
		&storedExecution, &storedAgent, &storedSandbox, &storedProjectID,
		&storedTaskID, &storedSeriesID, &storedModuleID, &storedFence,
	)
	if err != nil {
		return Assignment{}, err
	}
	if storedExecution != request.ExecutionID || storedAgent != agentID || storedSandbox != sandboxID || storedProjectID != request.Project.ID ||
		storedTaskID != request.Task.ID || storedSeriesID != attemptSeriesID || storedFence != targetFence || storedModuleID == "" {
		return Assignment{}, ErrAssignmentInvalid
	}
	if err := tx.Commit(); err != nil {
		return Assignment{}, err
	}
	return Assignment{AgentInstanceID: agentID, SandboxID: sandboxID, FencingToken: targetFence}, nil
}

func (authority *PostgresAssignmentAuthority) BindRuntime(ctx context.Context, request RuntimeBindingRequest) error {
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil || !validRuntimeBinding(request) {
		return ErrInvalidRequest
	}
	tx, err := authority.begin(ctx, request.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var agentID, projectID, taskID, seriesID string
	var fence int64
	var leaseID sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT agent_instance_id, project_id::text, module_task_id::text,
       attempt_series_id::text, fencing_token, lease_id
FROM execution_assignments
WHERE tenant_id = $1::uuid AND execution_id = $2
FOR UPDATE`, request.TenantID, request.ExecutionID).Scan(
		&agentID, &projectID, &taskID, &seriesID, &fence, &leaseID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssignmentInvalid
	}
	if err != nil {
		return err
	}
	if agentID != request.AgentInstanceID || projectID != request.ProjectID || taskID != request.TaskID || seriesID != request.AttemptSeriesID || fence != request.FencingToken || leaseID.Valid && leaseID.String != request.LeaseID {
		return ErrAssignmentInvalid
	}
	result, err := tx.ExecContext(ctx, `
UPDATE agent_instances
SET provider = $4, logical_model = $5, actual_model_version = $5,
    prompt_bundle_version = $6, state = 'LEASED'
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3
  AND role = 'EXECUTOR'
  AND prompt_bundle_version = $6
  AND (
    (state = 'DECLARED' AND provider = 'UNASSIGNED' AND logical_model = 'UNASSIGNED'
     AND actual_model_version = 'UNASSIGNED')
    OR
    (state = 'LEASED' AND provider = $4 AND logical_model = $5
     AND actual_model_version = $5)
  )`, request.TenantID, request.ProjectID, request.AgentInstanceID, request.Provider, request.Model, request.PromptVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrAssignmentInvalid
	}
	result, err = tx.ExecContext(ctx, `
UPDATE execution_assignments
SET lease_id = $3, runtime_bound_at = COALESCE(runtime_bound_at, transaction_timestamp())
WHERE tenant_id = $1::uuid AND execution_id = $2
  AND (lease_id IS NULL OR lease_id = $3)`, request.TenantID, request.ExecutionID, request.LeaseID)
	if err != nil {
		return err
	}
	rows, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrAssignmentInvalid
	}
	return tx.Commit()
}

func (authority *PostgresAssignmentAuthority) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	tx, err := authority.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if superuser || bypassRLS {
		_ = tx.Rollback()
		return nil, ErrAssignmentInvalid
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func validAssignmentRequest(request AssignmentRequest) bool {
	if !validID(request.ExecutionID) || !validID(request.Project.TenantID) || !validID(request.Project.ID) || !validID(request.Task.ID) ||
		request.Project.ID != request.Task.ProjectID || request.Project.TenantID != request.Task.TenantID || request.Project.State != contracts.ProjectExecuting || request.Project.PromptBundleVersion != prompts.BaselineVersion ||
		request.Task.ModuleID != request.ModuleSpec.ModuleID || request.Task.ProjectID != request.ModuleSpec.ProjectID || request.Task.ModuleSpecRef != moduleRef(request.ModuleSpec) ||
		request.Task.AttemptSeriesID == "" || request.Task.Attempt < 0 || request.Task.Attempt >= 3 {
		return false
	}
	return request.Task.State == contracts.TaskReadyExecution && !request.Recover || request.Task.State == contracts.TaskExecuting && request.Recover && request.Task.FencingToken > 0
}

func validRuntimeBinding(request RuntimeBindingRequest) bool {
	for _, value := range []string{request.ExecutionID, request.TenantID, request.ProjectID, request.TaskID, request.AttemptSeriesID, request.AgentInstanceID, request.LeaseID, request.Provider, request.Model, request.PromptVersion} {
		if strings.TrimSpace(value) != value || value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	return request.FencingToken > 0 && request.PromptVersion == prompts.BaselineVersion
}

func stableAssignmentID(prefix string, values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return prefix + hex.EncodeToString(digest.Sum(nil))
}

var _ AssignmentAuthority = (*PostgresAssignmentAuthority)(nil)
