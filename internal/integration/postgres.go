package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

type DurableRequest struct {
	TenantID       string
	ProjectID      string
	IntegrationID  string
	ProjectVersion int64
	CreatedAt      time.Time
}

type PostgresStore struct {
	database *sql.DB
}

func NewPostgresStore(database *sql.DB) (*PostgresStore, error) {
	if database == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresStore{database: database}, nil
}

func (store *PostgresStore) Request(ctx context.Context, tenantID, integrationID string) (DurableRequest, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !canonicalUUID(tenantID) || !canonicalUUID(integrationID) {
		return DurableRequest{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return DurableRequest{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var request DurableRequest
	err = tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, integration_id::text, project_version, created_at
FROM integration_requests
WHERE tenant_id = $1::uuid AND integration_id = $2::uuid`, tenantID, integrationID).Scan(
		&request.TenantID, &request.ProjectID, &request.IntegrationID, &request.ProjectVersion, &request.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DurableRequest{}, false, nil
	}
	if err != nil {
		return DurableRequest{}, false, err
	}
	request.CreatedAt = request.CreatedAt.UTC()
	if request.TenantID != tenantID || request.IntegrationID != integrationID || !canonicalUUID(request.ProjectID) || request.ProjectVersion < 1 || request.CreatedAt.IsZero() {
		return DurableRequest{}, false, ErrInvalidRequest
	}
	if err := tx.Commit(); err != nil {
		return DurableRequest{}, false, err
	}
	return request, true, nil
}

func (store *PostgresStore) Get(ctx context.Context, tenantID, integrationID string) (MergeResult, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !canonicalUUID(tenantID) || !canonicalUUID(integrationID) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return MergeResult{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, found, err := loadMergeResult(ctx, tx, tenantID, integrationID, false)
	if err != nil {
		return result, false, err
	}
	if !found {
		result, found, err = loadConflictResult(ctx, tx, tenantID, integrationID, false)
	}
	if err != nil || !found {
		return result, found, err
	}
	if err := tx.Commit(); err != nil {
		return MergeResult{}, false, err
	}
	return result, true, nil
}

func (store *PostgresStore) GetTask(ctx context.Context, tenantID, integrationID string) (IntegrationTask, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !canonicalUUID(tenantID) || !canonicalUUID(integrationID) {
		return IntegrationTask{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	task, found, err := loadIntegrationTask(ctx, tx, tenantID, integrationID, false)
	if err != nil || !found {
		return task, found, err
	}
	if err := tx.Commit(); err != nil {
		return IntegrationTask{}, false, err
	}
	return task, true, nil
}

func (store *PostgresStore) FindConflictByEvidence(ctx context.Context, tenantID, projectID, evidenceSHA256 string) (IntegrationTask, bool, error) {
	if store == nil || store.database == nil || ctx == nil || ctx.Err() != nil || !canonicalUUID(tenantID) || !canonicalUUID(projectID) || !digestPattern(evidenceSHA256) {
		return IntegrationTask{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var integrationID sql.NullString
	var matches int
	err = tx.QueryRowContext(ctx, `
SELECT min(id::text), count(*)
FROM integration_tasks
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
  AND conflict_jsonb->>'evidenceSha256' = $3`, tenantID, projectID, evidenceSHA256).Scan(&integrationID, &matches)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	if matches == 0 {
		return IntegrationTask{}, false, nil
	}
	if matches != 1 || !integrationID.Valid {
		return IntegrationTask{}, false, ErrImmutable
	}
	task, found, err := loadIntegrationTask(ctx, tx, tenantID, integrationID.String, false)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	if !found || task.ProjectID != projectID || task.Conflict.EvidenceSHA256 != evidenceSHA256 {
		return IntegrationTask{}, false, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return IntegrationTask{}, false, err
	}
	return task, true, nil
}

func (store *PostgresStore) StartAttempt(ctx context.Context, request StartAttemptRequest) (IntegrationTask, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !validStartAttemptRequest(request) ||
		!canonicalUUID(request.TenantID) || !canonicalUUID(request.ProjectID) || !canonicalUUID(request.IntegrationID) || !canonicalUUID(request.OwnerTaskID) {
		return IntegrationTask{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, request.TenantID, false)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	task, found, err := loadIntegrationTask(ctx, tx, request.TenantID, request.IntegrationID, true)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	if !found || task.ProjectID != request.ProjectID || task.OwnerTaskID != request.OwnerTaskID {
		return IntegrationTask{}, false, ErrAttemptState
	}
	if task.State == TaskBlockedUserDecision && task.Attempt == request.Attempt && task.Version > request.ExpectedVersion {
		return task, false, ErrAttemptsExhausted
	}
	if task.Attempt == request.Attempt && task.Version > request.ExpectedVersion {
		if err := tx.Commit(); err != nil {
			return IntegrationTask{}, false, err
		}
		return task, false, nil
	}
	if task.State != TaskReworkRequired || task.Version != request.ExpectedVersion || task.Attempt+1 != request.Attempt {
		return task, false, ErrAttemptState
	}
	operation, err := tx.ExecContext(ctx, `
UPDATE integration_tasks
SET state = 'EXECUTING', state_version = state_version + 1,
    attempt_count = $5, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND owner_module_task_id = $4::uuid AND state = 'REWORK_REQUIRED'
  AND state_version = $6 AND attempt_count = $5 - 1`,
		request.TenantID, request.ProjectID, request.IntegrationID, request.OwnerTaskID,
		request.Attempt, request.ExpectedVersion)
	if err != nil {
		return IntegrationTask{}, false, err
	}
	rows, err := operation.RowsAffected()
	if err != nil {
		return IntegrationTask{}, false, err
	}
	if rows != 1 {
		return IntegrationTask{}, false, ErrAttemptState
	}
	task.State = TaskExecuting
	task.Version++
	task.Attempt = request.Attempt
	if err := tx.Commit(); err != nil {
		return IntegrationTask{}, false, err
	}
	return task, true, nil
}

func (store *PostgresStore) RecordConflict(ctx context.Context, result MergeResult) (MergeResult, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !canonicalUUID(result.TenantID) || !canonicalUUID(result.ProjectID) || !canonicalUUID(result.IntegrationID) || !canonicalUUID(result.OwnerTaskID) || !validConflictResult(result) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	encoded, err := json.Marshal(result.Audit)
	if err != nil {
		return MergeResult{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, result.TenantID, false)
	if err != nil {
		return MergeResult{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	stored, changed, err := recordConflictInTransaction(ctx, tx, result, encoded)
	if err != nil {
		return MergeResult{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return MergeResult{}, false, err
	}
	return stored, changed, nil
}

func (store *PostgresStore) RecordGlobalAuditConflict(ctx context.Context, result MergeResult, expectedProjectVersion int64) (MergeResult, bool, error) {
	if store == nil || store.database == nil || ctx == nil || expectedProjectVersion < 1 || result.Attempt != 0 ||
		!canonicalUUID(result.TenantID) || !canonicalUUID(result.ProjectID) || !canonicalUUID(result.IntegrationID) ||
		!canonicalUUID(result.OwnerTaskID) || !validConflictResult(result) || !globalAuditConflictEvidence(result) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	encoded, err := json.Marshal(result.Audit)
	if err != nil {
		return MergeResult{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, result.TenantID, false)
	if err != nil {
		return MergeResult{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var projectState string
	var projectVersion int64
	err = tx.QueryRowContext(ctx, `
SELECT state, state_version
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR UPDATE`, result.TenantID, result.ProjectID).Scan(&projectState, &projectVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return MergeResult{}, false, ErrNotAudited
	}
	if err != nil {
		return MergeResult{}, false, err
	}
	if projectState != "GLOBAL_AUDIT" || projectVersion != expectedProjectVersion {
		return MergeResult{}, false, ErrNotAudited
	}
	stored, changed, err := recordConflictInTransaction(ctx, tx, result, encoded)
	if err != nil {
		return MergeResult{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return MergeResult{}, false, err
	}
	return stored, changed, nil
}

func recordConflictInTransaction(ctx context.Context, tx *sql.Tx, result MergeResult, encoded []byte) (MergeResult, bool, error) {
	task, found, err := loadIntegrationTask(ctx, tx, result.TenantID, result.IntegrationID, true)
	if err != nil {
		return MergeResult{}, false, err
	}
	changed := false
	if !found {
		if result.Attempt != 0 {
			return MergeResult{}, false, ErrAttemptState
		}
		operation, err := tx.ExecContext(ctx, `
INSERT INTO integration_tasks
  (id, tenant_id, project_id, state, state_version, attempt_count,
   owner_module_task_id, conflict_jsonb, created_at, updated_at)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, 'REWORK_REQUIRED', 1, 0,
   $4::uuid, $5::jsonb, transaction_timestamp(), transaction_timestamp())
ON CONFLICT (id) DO NOTHING`, result.IntegrationID, result.TenantID, result.ProjectID, result.OwnerTaskID, encoded)
		if err != nil {
			return MergeResult{}, false, err
		}
		rows, err := operation.RowsAffected()
		if err != nil {
			return MergeResult{}, false, err
		}
		changed = rows == 1
		task, found, err = loadIntegrationTask(ctx, tx, result.TenantID, result.IntegrationID, true)
		if err != nil {
			return MergeResult{}, false, err
		}
	}
	if !found || task.ProjectID != result.ProjectID {
		return MergeResult{}, false, ErrImmutable
	}
	stored, storedConflict, err := loadConflictResult(ctx, tx, result.TenantID, result.IntegrationID, false)
	if err != nil {
		return MergeResult{}, false, err
	}
	if task.State == TaskReworkRequired || task.State == TaskBlockedUserDecision {
		if storedConflict && sameConflictResult(stored, result) {
			return stored, changed, nil
		}
		return MergeResult{}, false, ErrImmutable
	}
	if changed {
		return MergeResult{}, false, ErrImmutable
	}
	initialMergeFailure := result.Attempt == 0 && task.State == TaskMergeReserved && task.Attempt == 0 && task.OwnerTaskID == "" && isMergeFailureAudit(result.Audit, result.OwnerTaskID)
	reworkFailure := result.Attempt > 0 && task.Attempt == result.Attempt && task.OwnerTaskID == result.OwnerTaskID &&
		(task.State == TaskExecuting || task.State == TaskMergeReserved && isMergeFailureAudit(result.Audit, result.OwnerTaskID))
	if !initialMergeFailure && !reworkFailure {
		return MergeResult{}, false, ErrAttemptState
	}
	nextState := TaskReworkRequired
	if result.Attempt == 3 {
		nextState = TaskBlockedUserDecision
	}
	operation, err := tx.ExecContext(ctx, `
UPDATE integration_tasks
SET state = $4, state_version = state_version + 1,
    owner_module_task_id = $5::uuid, conflict_jsonb = $6::jsonb,
    merge_request_sha256 = NULL, merge_audit_sha256 = NULL,
    merge_result_jsonb = NULL, merge_commit = NULL, merge_pending = NULL,
    updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND state_version = $7 AND attempt_count = $8`,
		result.TenantID, result.ProjectID, result.IntegrationID, string(nextState),
		result.OwnerTaskID, encoded, task.Version, result.Attempt)
	if err != nil {
		return MergeResult{}, false, err
	}
	rows, err := operation.RowsAffected()
	if err != nil {
		return MergeResult{}, false, err
	}
	if rows != 1 {
		return MergeResult{}, false, ErrAttemptState
	}
	stored, storedConflict, err = loadConflictResult(ctx, tx, result.TenantID, result.IntegrationID, false)
	if err != nil {
		return MergeResult{}, false, err
	}
	if !storedConflict || !sameConflictResult(stored, result) {
		return MergeResult{}, false, ErrImmutable
	}
	return stored, true, nil
}

func (store *PostgresStore) Reserve(ctx context.Context, result MergeResult) (MergeResult, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !validMergeResult(result, true) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return MergeResult{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, result.TenantID, false)
	if err != nil {
		return MergeResult{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	task, found, err := loadIntegrationTask(ctx, tx, result.TenantID, result.IntegrationID, true)
	if err != nil {
		return MergeResult{}, false, err
	}
	if found {
		stored, storedMerge, err := loadMergeResult(ctx, tx, result.TenantID, result.IntegrationID, false)
		if err != nil {
			return MergeResult{}, false, err
		}
		if storedMerge && stored.ProjectID == result.ProjectID && stored.RequestDigest == result.RequestDigest && stored.Audit.EvidenceSHA256 == result.Audit.EvidenceSHA256 && stored.OwnerTaskID == result.OwnerTaskID && stored.Attempt == result.Attempt {
			if task.State == TaskDone && (stored.LeaseID != result.LeaseID || stored.FencingToken != result.FencingToken) {
				return MergeResult{}, false, ErrImmutable
			}
			if err := tx.Commit(); err != nil {
				return MergeResult{}, false, err
			}
			return stored, false, nil
		}
		if storedMerge {
			return MergeResult{}, false, ErrImmutable
		}
		if result.Attempt == 0 || task.ProjectID != result.ProjectID || task.State != TaskExecuting || task.OwnerTaskID != result.OwnerTaskID || task.Attempt != result.Attempt {
			return MergeResult{}, false, ErrAttemptState
		}
		operation, err := tx.ExecContext(ctx, `
UPDATE integration_tasks
SET state = 'MERGE_RESERVED', state_version = state_version + 1,
    merge_request_sha256 = $4, merge_audit_sha256 = $5,
    merge_result_jsonb = $6::jsonb, merge_commit = NULL,
    merge_pending = true, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND owner_module_task_id = $7::uuid AND attempt_count = $8
  AND state = 'EXECUTING' AND state_version = $9
  AND merge_request_sha256 IS NULL AND merge_audit_sha256 IS NULL
  AND merge_result_jsonb IS NULL AND merge_commit IS NULL AND merge_pending IS NULL`,
			result.TenantID, result.ProjectID, result.IntegrationID,
			result.RequestDigest, result.Audit.EvidenceSHA256, encoded,
			result.OwnerTaskID, result.Attempt, task.Version)
		if err != nil {
			return MergeResult{}, false, err
		}
		rows, err := operation.RowsAffected()
		if err != nil {
			return MergeResult{}, false, err
		}
		if rows != 1 {
			return MergeResult{}, false, ErrAttemptState
		}
	} else {
		if result.Attempt != 0 || result.OwnerTaskID != "" {
			return MergeResult{}, false, ErrAttemptState
		}
		operation, err := tx.ExecContext(ctx, `
INSERT INTO integration_tasks
  (id, tenant_id, project_id, state, state_version, attempt_count,
   conflict_jsonb, merge_request_sha256, merge_audit_sha256,
   merge_result_jsonb, merge_pending, created_at, updated_at)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, 'MERGE_RESERVED', 1, 0,
   '{}'::jsonb, $4, $5, $6::jsonb, true, transaction_timestamp(), transaction_timestamp())
ON CONFLICT (id) DO NOTHING`, result.IntegrationID, result.TenantID, result.ProjectID, result.RequestDigest, result.Audit.EvidenceSHA256, encoded)
		if err != nil {
			return MergeResult{}, false, err
		}
		rows, err := operation.RowsAffected()
		if err != nil {
			return MergeResult{}, false, err
		}
		if rows != 1 {
			stored, storedMerge, err := loadMergeResult(ctx, tx, result.TenantID, result.IntegrationID, true)
			if err != nil {
				return MergeResult{}, false, err
			}
			if !storedMerge || stored.ProjectID != result.ProjectID || stored.RequestDigest != result.RequestDigest || stored.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 {
				return MergeResult{}, false, ErrImmutable
			}
			if err := tx.Commit(); err != nil {
				return MergeResult{}, false, err
			}
			return stored, false, nil
		}
	}
	stored, storedMerge, err := loadMergeResult(ctx, tx, result.TenantID, result.IntegrationID, true)
	if err != nil {
		return MergeResult{}, false, err
	}
	if !storedMerge || stored.ProjectID != result.ProjectID || stored.RequestDigest != result.RequestDigest || stored.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 || stored.OwnerTaskID != result.OwnerTaskID || stored.Attempt != result.Attempt {
		return MergeResult{}, false, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return MergeResult{}, false, err
	}
	return stored, true, nil
}

func (store *PostgresStore) Complete(ctx context.Context, result MergeResult) error {
	if store == nil || store.database == nil || ctx == nil || !validMergeResult(result, false) {
		return ErrInvalidRequest
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return ErrInvalidRequest
	}
	tx, err := store.begin(ctx, result.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stored, found, err := loadMergeResult(ctx, tx, result.TenantID, result.IntegrationID, true)
	if err != nil {
		return err
	}
	if !found || stored.ProjectID != result.ProjectID || stored.RequestDigest != result.RequestDigest || stored.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 || stored.OwnerTaskID != result.OwnerTaskID || stored.Attempt != result.Attempt {
		return ErrImmutable
	}
	if !stored.Pending {
		if stored.LeaseID != result.LeaseID || stored.FencingToken != result.FencingToken {
			return ErrImmutable
		}
		if stored.Commit != result.Commit {
			return ErrImmutable
		}
		return tx.Commit()
	}
	operation, err := tx.ExecContext(ctx, `
UPDATE integration_tasks
SET state = 'DONE', state_version = state_version + 1,
    merge_result_jsonb = $4::jsonb, merge_commit = $5,
    merge_pending = false, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND merge_request_sha256 = $6 AND merge_audit_sha256 = $7
  AND owner_module_task_id IS NOT DISTINCT FROM NULLIF($8::text, '')::uuid
  AND attempt_count = $9 AND state = 'MERGE_RESERVED'
  AND merge_pending = true`, result.TenantID, result.ProjectID, result.IntegrationID, encoded, result.Commit, result.RequestDigest, result.Audit.EvidenceSHA256, result.OwnerTaskID, result.Attempt)
	if err != nil {
		return err
	}
	rows, err := operation.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrImmutable
	}
	return tx.Commit()
}

func (store *PostgresStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func loadMergeResult(ctx context.Context, tx *sql.Tx, tenantID, integrationID string, lock bool) (MergeResult, bool, error) {
	query := `
SELECT project_id::text, merge_request_sha256, merge_audit_sha256,
       merge_result_jsonb, merge_commit, merge_pending,
       owner_module_task_id::text, attempt_count, state
FROM integration_tasks
WHERE tenant_id = $1::uuid AND id = $2::uuid
  AND merge_result_jsonb IS NOT NULL`
	if lock {
		query += " FOR UPDATE"
	}
	var projectID, requestDigest, auditDigest string
	var encoded []byte
	var commit, ownerTaskID sql.NullString
	var pending bool
	var attempt int
	var state TaskState
	err := tx.QueryRowContext(ctx, query, tenantID, integrationID).Scan(&projectID, &requestDigest, &auditDigest, &encoded, &commit, &pending, &ownerTaskID, &attempt, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return MergeResult{}, false, nil
	}
	if err != nil {
		return MergeResult{}, false, err
	}
	result, err := decodeMergeResult(encoded)
	expectedState := TaskDone
	if pending {
		expectedState = TaskMergeReserved
	}
	if err != nil || state != expectedState || result.TenantID != tenantID || result.ProjectID != projectID || result.IntegrationID != integrationID || result.OwnerTaskID != ownerTaskID.String || result.Attempt != attempt || result.RequestDigest != requestDigest || result.Audit.EvidenceSHA256 != auditDigest || result.Pending != pending || result.Commit != commit.String || !validMergeResult(result, pending) {
		return MergeResult{}, false, ErrImmutable
	}
	return result, true, nil
}

func loadConflictResult(ctx context.Context, tx *sql.Tx, tenantID, integrationID string, lock bool) (MergeResult, bool, error) {
	query := `
SELECT project_id::text, owner_module_task_id::text, attempt_count, conflict_jsonb
FROM integration_tasks
WHERE tenant_id = $1::uuid AND id = $2::uuid
  AND state IN ('REWORK_REQUIRED', 'EXECUTING', 'BLOCKED_USER_DECISION')
  AND owner_module_task_id IS NOT NULL
  AND merge_request_sha256 IS NULL AND merge_audit_sha256 IS NULL
  AND merge_result_jsonb IS NULL AND merge_commit IS NULL AND merge_pending IS NULL`
	if lock {
		query += " FOR UPDATE"
	}
	var projectID, ownerTaskID string
	var attempt int
	var encoded []byte
	err := tx.QueryRowContext(ctx, query, tenantID, integrationID).Scan(&projectID, &ownerTaskID, &attempt, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return MergeResult{}, false, nil
	}
	if err != nil {
		return MergeResult{}, false, err
	}
	audit, err := decodeConflictAudit(encoded)
	result := MergeResult{TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID, OwnerTaskID: ownerTaskID, Attempt: attempt, Audit: audit}
	if err != nil || !validConflictResult(result) {
		return MergeResult{}, false, ErrImmutable
	}
	return result, true, nil
}

func loadIntegrationTask(ctx context.Context, tx *sql.Tx, tenantID, integrationID string, lock bool) (IntegrationTask, bool, error) {
	query := `
SELECT project_id::text, owner_module_task_id::text, state, state_version,
       attempt_count, conflict_jsonb
FROM integration_tasks
WHERE tenant_id = $1::uuid AND id = $2::uuid`
	if lock {
		query += " FOR UPDATE"
	}
	var task IntegrationTask
	var ownerTaskID sql.NullString
	var encoded []byte
	task.TenantID = tenantID
	task.ID = integrationID
	err := tx.QueryRowContext(ctx, query, tenantID, integrationID).Scan(
		&task.ProjectID, &ownerTaskID, &task.State, &task.Version, &task.Attempt, &encoded,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return IntegrationTask{}, false, nil
	}
	if err != nil {
		return IntegrationTask{}, false, err
	}
	task.OwnerTaskID = ownerTaskID.String
	if len(encoded) > 0 && string(encoded) != "{}" {
		audit, err := decodeConflictAudit(encoded)
		if err != nil {
			return IntegrationTask{}, false, ErrImmutable
		}
		task.Conflict = audit
	}
	if !validIntegrationTask(task) {
		return IntegrationTask{}, false, ErrImmutable
	}
	return task, true, nil
}

func decodeMergeResult(encoded []byte) (MergeResult, error) {
	var result MergeResult
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return MergeResult{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return MergeResult{}, ErrImmutable
	}
	return result, nil
}

func decodeConflictAudit(encoded []byte) (Audit, error) {
	var audit Audit
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&audit); err != nil {
		return Audit{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Audit{}, ErrImmutable
	}
	return audit, nil
}

func validMergeResult(result MergeResult, pending bool) bool {
	if !canonicalUUID(result.TenantID) || !canonicalUUID(result.ProjectID) || !canonicalUUID(result.IntegrationID) || !digestPattern(result.RequestDigest) || result.Pending != pending ||
		result.Audit.IntegrationID != result.IntegrationID || result.Audit.ProjectID != result.ProjectID || !result.Audit.Passed || len(result.Audit.Findings) != 0 || !digestPattern(result.Audit.EvidenceSHA256) || result.Audit.CreatedAt.IsZero() {
		return false
	}
	if result.Checks != nil && !validCheckResults(result.Checks, true) {
		return false
	}
	if !validStoredCandidates(result.Candidates) {
		return false
	}
	if !validAttemptBinding(result.OwnerTaskID, result.Attempt) || result.Attempt > 0 && !canonicalUUID(result.OwnerTaskID) {
		return false
	}
	if pending {
		return result.Commit == ""
	}
	return commitID(result.Commit)
}

func validIntegrationTask(task IntegrationTask) bool {
	if !canonicalUUID(task.TenantID) || !canonicalUUID(task.ProjectID) || !canonicalUUID(task.ID) || task.Version < 1 || task.Attempt < 0 || task.Attempt > 3 {
		return false
	}
	boundOwner := canonicalUUID(task.OwnerTaskID)
	validConflict := task.Conflict.IntegrationID == task.ID && task.Conflict.ProjectID == task.ProjectID &&
		!task.Conflict.Passed && len(task.Conflict.Findings) > 0 && digestPattern(task.Conflict.EvidenceSHA256) && !task.Conflict.CreatedAt.IsZero()
	switch task.State {
	case TaskReworkRequired:
		return boundOwner && task.Attempt < 3 && validConflict
	case TaskExecuting:
		return boundOwner && task.Attempt >= 1 && validConflict
	case TaskBlockedUserDecision:
		return boundOwner && task.Attempt == 3 && validConflict
	case TaskMergeReserved, TaskDone:
		return task.Attempt == 0 && task.OwnerTaskID == "" || task.Attempt >= 1 && boundOwner
	default:
		return false
	}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == strings.ToLower(value)
}

var _ Store = (*PostgresStore)(nil)
