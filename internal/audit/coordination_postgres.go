package audit

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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
