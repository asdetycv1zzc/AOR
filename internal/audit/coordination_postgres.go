package audit

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/pkg/contracts"
)

type PostgresCoordinationStore struct {
	database *sql.DB
}

func NewPostgresCoordinationStore(database *sql.DB) (*PostgresCoordinationStore, error) {
	if database == nil {
		return nil, ErrAuditServiceUnavailable
	}
	return &PostgresCoordinationStore{database: database}, nil
}

func (store *PostgresCoordinationStore) Get(ctx context.Context, tenantID, taskID, attemptSeriesID string, attempt int) (Coordination, bool, error) {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil ||
		!canonicalAuditUUID(tenantID) || !canonicalAuditUUID(taskID) || !canonicalAuditUUID(attemptSeriesID) || attempt < 1 || attempt > 3 {
		return Coordination{}, false, ErrInvalidAuditRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return Coordination{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	value, found, err := loadCoordination(ctx, tx, tenantID, taskID, attemptSeriesID, attempt, false)
	if err != nil || !found {
		return Coordination{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return Coordination{}, false, err
	}
	return value, true, nil
}

func (store *PostgresCoordinationStore) Claim(ctx context.Context, requested Coordination) (Coordination, bool, error) {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil || !validPostgresCoordination(requested) || requested.State != coordinationDeterministic {
		return Coordination{}, false, ErrInvalidAuditRequest
	}
	tx, err := store.begin(ctx, requested.TenantID, false)
	if err != nil {
		return Coordination{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO module_audit_coordinations
  (tenant_id, project_id, module_task_id, attempt_series_id, attempt,
   submission_id, audit_run_id, input_sha256, policy_digest,
   execution_platform, isolation_level, sandbox_attestation, state)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6::uuid, $7::uuid, $8,
   $9, $10, $11, $12, $13)
ON CONFLICT DO NOTHING`, requested.TenantID, requested.ProjectID, requested.TaskID,
		requested.AttemptSeriesID, requested.Attempt, requested.SubmissionID, requested.AuditRunID,
		requested.InputSHA256, requested.Facts.PolicyDigest, requested.Facts.Platform,
		requested.Facts.Isolation, requested.Facts.SandboxAttestation, requested.State)
	if err != nil {
		return Coordination{}, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Coordination{}, false, err
	}
	current, found, err := loadCoordination(ctx, tx, requested.TenantID, requested.TaskID, requested.AttemptSeriesID, requested.Attempt, true)
	if err != nil {
		return Coordination{}, false, err
	}
	if !found || !sameCoordinationClaim(current, requested) {
		return Coordination{}, false, ErrAuditInProgress
	}
	if err := tx.Commit(); err != nil {
		return Coordination{}, false, err
	}
	return current, inserted == 0, nil
}

func (store *PostgresCoordinationStore) MarkDeterministic(ctx context.Context, expected Coordination, digest string) (Coordination, error) {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil ||
		!validPostgresCoordination(expected) || !digestPattern.MatchString(digest) {
		return Coordination{}, ErrInvalidAuditRequest
	}
	tx, err := store.begin(ctx, expected.TenantID, false)
	if err != nil {
		return Coordination{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, found, err := loadCoordination(ctx, tx, expected.TenantID, expected.TaskID, expected.AttemptSeriesID, expected.Attempt, true)
	if err != nil {
		return Coordination{}, err
	}
	if !found || !sameCoordinationClaim(current, expected) {
		return Coordination{}, ErrAuditRecoveryConflict
	}
	if current.State == coordinationLLM || current.State == coordinationCompleted {
		if current.DeterministicSHA256 != digest {
			return Coordination{}, ErrAuditRecoveryConflict
		}
		if err := tx.Commit(); err != nil {
			return Coordination{}, err
		}
		return current, nil
	}
	if current.State != coordinationDeterministic {
		return Coordination{}, ErrAuditRecoveryConflict
	}
	_, err = tx.ExecContext(ctx, `
UPDATE module_audit_coordinations
SET state = $6, deterministic_sha256 = $7, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND module_task_id = $2::uuid
  AND attempt_series_id = $3::uuid AND attempt = $4 AND audit_run_id = $5::uuid`,
		expected.TenantID, expected.TaskID, expected.AttemptSeriesID, expected.Attempt,
		expected.AuditRunID, coordinationLLM, digest)
	if err != nil {
		return Coordination{}, err
	}
	current.State = coordinationLLM
	current.DeterministicSHA256 = digest
	if err := tx.Commit(); err != nil {
		return Coordination{}, err
	}
	return current, nil
}

func (store *PostgresCoordinationStore) Complete(ctx context.Context, expected Coordination, evidenceDigest, outcome string) (Coordination, error) {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil ||
		!validPostgresCoordination(expected) || !digestPattern.MatchString(evidenceDigest) || !validCoordinationOutcome(outcome) {
		return Coordination{}, ErrInvalidAuditRequest
	}
	tx, err := store.begin(ctx, expected.TenantID, false)
	if err != nil {
		return Coordination{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, found, err := loadCoordination(ctx, tx, expected.TenantID, expected.TaskID, expected.AttemptSeriesID, expected.Attempt, true)
	if err != nil {
		return Coordination{}, err
	}
	if !found || !sameCoordinationClaim(current, expected) {
		return Coordination{}, ErrAuditRecoveryConflict
	}
	if current.State == coordinationCompleted {
		if current.EvidenceSHA256 != evidenceDigest || current.Outcome != outcome {
			return Coordination{}, ErrAuditRecoveryConflict
		}
		if err := tx.Commit(); err != nil {
			return Coordination{}, err
		}
		return current, nil
	}
	if outcome == outcomeDeterministicFail && current.State != coordinationDeterministic ||
		outcome != outcomeDeterministicFail && current.State != coordinationLLM {
		return Coordination{}, ErrAuditRecoveryConflict
	}
	_, err = tx.ExecContext(ctx, `
UPDATE module_audit_coordinations
SET state = $6, evidence_sha256 = $7, outcome = $8,
    completed_at = transaction_timestamp(), updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND module_task_id = $2::uuid
  AND attempt_series_id = $3::uuid AND attempt = $4 AND audit_run_id = $5::uuid`,
		expected.TenantID, expected.TaskID, expected.AttemptSeriesID, expected.Attempt,
		expected.AuditRunID, coordinationCompleted, evidenceDigest, outcome)
	if err != nil {
		return Coordination{}, err
	}
	current.State = coordinationCompleted
	current.EvidenceSHA256 = evidenceDigest
	current.Outcome = outcome
	if err := tx.Commit(); err != nil {
		return Coordination{}, err
	}
	return current, nil
}

func (store *PostgresCoordinationStore) Register(ctx context.Context, registration ModuleAuditAgentRegistration) error {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil || !validModuleAuditAgentRegistration(registration) {
		return ErrInvalidAuditRequest
	}
	tx, err := store.begin(ctx, registration.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var projectState, taskState, seriesID, coordinationState string
	var projectVersion, taskVersion int64
	var attempt int
	err = tx.QueryRowContext(ctx, `
SELECT project.state, project.state_version, task.state, task.state_version,
       task.active_attempt_series_id::text, task.attempt_count, coordination.state
FROM projects AS project
JOIN module_tasks AS task
  ON task.tenant_id = project.tenant_id AND task.project_id = project.id
JOIN module_audit_coordinations AS coordination
  ON coordination.tenant_id = task.tenant_id
 AND coordination.project_id = task.project_id
 AND coordination.module_task_id = task.id
 AND coordination.attempt_series_id = task.active_attempt_series_id
 AND coordination.attempt = task.attempt_count
WHERE project.tenant_id = $1::uuid AND project.id = $2::uuid
  AND task.id = $3::uuid AND coordination.audit_run_id = $4::uuid
FOR UPDATE OF task, coordination`, registration.TenantID, registration.ProjectID,
		registration.TaskID, registration.AuditRunID).Scan(
		&projectState, &projectVersion, &taskState, &taskVersion,
		&seriesID, &attempt, &coordinationState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuditRecoveryConflict
	}
	if err != nil {
		return err
	}
	if projectState != string(contracts.ProjectExecuting) || projectVersion != registration.ProjectVersion ||
		taskState != string(contracts.TaskLLMAudit) || taskVersion != registration.TaskVersion ||
		seriesID != registration.AttemptSeriesID || attempt != registration.Attempt || coordinationState != coordinationLLM {
		return ErrAuditRecoveryConflict
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
VALUES ($1, $2::uuid, $3::uuid, 'MODULE_AUDITOR', $4, $5, $5, $6,
        'DECLARED', transaction_timestamp())
ON CONFLICT (id) DO NOTHING`, registration.AgentInstanceID, registration.TenantID,
		registration.ProjectID, registration.Provider, registration.Model, registration.PromptBundleVersion)
	if err != nil {
		return err
	}
	var tenantID, projectID, role, provider, logicalModel, actualModel, promptVersion, state string
	err = tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, role, provider, logical_model,
       actual_model_version, prompt_bundle_version, state
FROM agent_instances
WHERE tenant_id = $1::uuid AND id = $2`, registration.TenantID, registration.AgentInstanceID).Scan(
		&tenantID, &projectID, &role, &provider, &logicalModel, &actualModel, &promptVersion, &state,
	)
	if err != nil {
		return err
	}
	if tenantID != registration.TenantID || projectID != registration.ProjectID || role != string(agentruntime.RoleModuleAuditor) ||
		provider != registration.Provider || logicalModel != registration.Model || actualModel != registration.Model ||
		promptVersion != registration.PromptBundleVersion || state != "DECLARED" {
		return ErrAuditRecoveryConflict
	}
	return tx.Commit()
}

func (store *PostgresCoordinationStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		_ = tx.Rollback()
		if err != nil {
			return nil, err
		}
		return nil, ErrAuditAuthorization
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func loadCoordination(ctx context.Context, tx *sql.Tx, tenantID, taskID, attemptSeriesID string, attempt int, lock bool) (Coordination, bool, error) {
	query := `
SELECT project_id::text, submission_id::text, audit_run_id::text, input_sha256,
       policy_digest, execution_platform, isolation_level, sandbox_attestation,
       state, deterministic_sha256, evidence_sha256, outcome
FROM module_audit_coordinations
WHERE tenant_id = $1::uuid AND module_task_id = $2::uuid
  AND attempt_series_id = $3::uuid AND attempt = $4`
	if lock {
		query += " FOR UPDATE"
	}
	value := Coordination{TenantID: tenantID, TaskID: taskID, AttemptSeriesID: attemptSeriesID, Attempt: attempt}
	var deterministic, evidence, outcome sql.NullString
	err := tx.QueryRowContext(ctx, query, tenantID, taskID, attemptSeriesID, attempt).Scan(
		&value.ProjectID, &value.SubmissionID, &value.AuditRunID, &value.InputSHA256,
		&value.Facts.PolicyDigest, &value.Facts.Platform, &value.Facts.Isolation,
		&value.Facts.SandboxAttestation, &value.State, &deterministic, &evidence, &outcome,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Coordination{}, false, nil
	}
	if err != nil {
		return Coordination{}, false, err
	}
	value.DeterministicSHA256 = deterministic.String
	value.EvidenceSHA256 = evidence.String
	value.Outcome = outcome.String
	if !validPostgresCoordination(value) {
		return Coordination{}, false, ErrAuditRecoveryConflict
	}
	return value, true, nil
}

func validPostgresCoordination(value Coordination) bool {
	if !canonicalAuditUUID(value.TenantID) || !canonicalAuditUUID(value.ProjectID) || !canonicalAuditUUID(value.TaskID) ||
		!canonicalAuditUUID(value.AttemptSeriesID) || !canonicalAuditUUID(value.SubmissionID) ||
		!validAuditRunID(value.AuditRunID) || value.Attempt < 1 || value.Attempt > 3 ||
		!digestPattern.MatchString(value.InputSHA256) || !validStoredRuntimeFacts(value.Facts) {
		return false
	}
	switch value.State {
	case coordinationDeterministic:
		return value.DeterministicSHA256 == "" && value.EvidenceSHA256 == "" && value.Outcome == ""
	case coordinationLLM:
		return digestPattern.MatchString(value.DeterministicSHA256) && value.EvidenceSHA256 == "" && value.Outcome == ""
	case coordinationCompleted:
		if !digestPattern.MatchString(value.EvidenceSHA256) || !validCoordinationOutcome(value.Outcome) {
			return false
		}
		return value.Outcome == outcomeDeterministicFail && value.DeterministicSHA256 == "" ||
			value.Outcome != outcomeDeterministicFail && digestPattern.MatchString(value.DeterministicSHA256)
	default:
		return false
	}
}

func validModuleAuditAgentRegistration(registration ModuleAuditAgentRegistration) bool {
	if !canonicalAuditUUID(registration.TenantID) || !canonicalAuditUUID(registration.ProjectID) ||
		!canonicalAuditUUID(registration.TaskID) || !canonicalAuditUUID(registration.AttemptSeriesID) ||
		!validAuditRunID(registration.AuditRunID) || registration.ProjectVersion < 1 || registration.TaskVersion < 1 ||
		registration.Attempt < 1 || registration.Attempt > 3 ||
		registration.AgentInstanceID != stableModuleAuditID("module-auditor-", registration.AuditRunID, registration.TaskID) {
		return false
	}
	for _, value := range []string{registration.Provider, registration.Model, registration.PromptBundleVersion} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	return len(registration.Provider) <= 128
}

func validStoredRuntimeFacts(facts RuntimeFacts) bool {
	if !digestPattern.MatchString(facts.PolicyDigest) || len(facts.SandboxAttestation) == 0 || len(facts.SandboxAttestation) > 4096 {
		return false
	}
	return facts.Platform == "LINUX" && facts.Isolation == "CONTAINER" && strings.HasPrefix(facts.SandboxAttestation, "oci:sha256:") ||
		facts.Platform == "WINDOWS" && facts.Isolation == "NONE" && facts.SandboxAttestation == "windows:none"
}

func sameCoordinationClaim(left, right Coordination) bool {
	return left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.TaskID == right.TaskID &&
		left.AttemptSeriesID == right.AttemptSeriesID && left.Attempt == right.Attempt &&
		left.SubmissionID == right.SubmissionID && left.AuditRunID == right.AuditRunID &&
		left.InputSHA256 == right.InputSHA256 && left.Facts == right.Facts
}

func validCoordinationOutcome(value string) bool {
	return value == outcomeDeterministicFail || value == outcomeLLMSuccess || value == outcomeLLMFailure
}

var _ CoordinationStore = (*PostgresCoordinationStore)(nil)
var _ ModuleAuditAgentRegistry = (*PostgresCoordinationStore)(nil)
