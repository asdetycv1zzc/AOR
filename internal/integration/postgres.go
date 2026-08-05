package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/google/uuid"
)

type PostgresStore struct {
	database *sql.DB
}

func NewPostgresStore(database *sql.DB) (*PostgresStore, error) {
	if database == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresStore{database: database}, nil
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

func (store *PostgresStore) RecordConflict(ctx context.Context, result MergeResult) (MergeResult, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !canonicalUUID(result.TenantID) || !canonicalUUID(result.ProjectID) || !canonicalUUID(result.IntegrationID) || !validConflictResult(result) {
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
	operation, err := tx.ExecContext(ctx, `
INSERT INTO integration_tasks
  (id, tenant_id, project_id, state, state_version, attempt_count,
   conflict_jsonb, created_at, updated_at)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, 'REWORK_REQUIRED', 1, 0,
   $4::jsonb, transaction_timestamp(), transaction_timestamp())
ON CONFLICT (id) DO NOTHING`, result.IntegrationID, result.TenantID, result.ProjectID, encoded)
	if err != nil {
		return MergeResult{}, false, err
	}
	rows, err := operation.RowsAffected()
	if err != nil {
		return MergeResult{}, false, err
	}
	stored, found, err := loadConflictResult(ctx, tx, result.TenantID, result.IntegrationID, true)
	if err != nil {
		return MergeResult{}, false, err
	}
	if !found || !sameConflictResult(stored, result) {
		return MergeResult{}, false, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return MergeResult{}, false, err
	}
	return stored, rows == 1, nil
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
	stored, found, err := loadMergeResult(ctx, tx, result.TenantID, result.IntegrationID, true)
	if err != nil {
		return MergeResult{}, false, err
	}
	if !found || stored.ProjectID != result.ProjectID || stored.RequestDigest != result.RequestDigest || stored.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 {
		return MergeResult{}, false, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return MergeResult{}, false, err
	}
	return stored, rows == 1, nil
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
	if !found || stored.ProjectID != result.ProjectID || stored.RequestDigest != result.RequestDigest || stored.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 {
		return ErrImmutable
	}
	if !stored.Pending {
		if stored.Commit != result.Commit {
			return ErrImmutable
		}
		return tx.Commit()
	}
	operation, err := tx.ExecContext(ctx, `
UPDATE integration_tasks
SET state = 'MERGED', state_version = state_version + 1,
    merge_result_jsonb = $4::jsonb, merge_commit = $5,
    merge_pending = false, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND merge_request_sha256 = $6 AND merge_audit_sha256 = $7
  AND merge_pending = true`, result.TenantID, result.ProjectID, result.IntegrationID, encoded, result.Commit, result.RequestDigest, result.Audit.EvidenceSHA256)
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
       merge_result_jsonb, merge_commit, merge_pending
FROM integration_tasks
WHERE tenant_id = $1::uuid AND id = $2::uuid
  AND merge_result_jsonb IS NOT NULL`
	if lock {
		query += " FOR UPDATE"
	}
	var projectID, requestDigest, auditDigest string
	var encoded []byte
	var commit sql.NullString
	var pending bool
	err := tx.QueryRowContext(ctx, query, tenantID, integrationID).Scan(&projectID, &requestDigest, &auditDigest, &encoded, &commit, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return MergeResult{}, false, nil
	}
	if err != nil {
		return MergeResult{}, false, err
	}
	result, err := decodeMergeResult(encoded)
	if err != nil || result.TenantID != tenantID || result.ProjectID != projectID || result.IntegrationID != integrationID || result.RequestDigest != requestDigest || result.Audit.EvidenceSHA256 != auditDigest || result.Pending != pending || result.Commit != commit.String || !validMergeResult(result, pending) {
		return MergeResult{}, false, ErrImmutable
	}
	return result, true, nil
}

func loadConflictResult(ctx context.Context, tx *sql.Tx, tenantID, integrationID string, lock bool) (MergeResult, bool, error) {
	query := `
SELECT project_id::text, conflict_jsonb
FROM integration_tasks
WHERE tenant_id = $1::uuid AND id = $2::uuid
  AND state = 'REWORK_REQUIRED' AND state_version = 1 AND attempt_count = 0
  AND owner_module_task_id IS NULL
  AND merge_request_sha256 IS NULL AND merge_audit_sha256 IS NULL
  AND merge_result_jsonb IS NULL AND merge_commit IS NULL AND merge_pending IS NULL`
	if lock {
		query += " FOR UPDATE"
	}
	var projectID string
	var encoded []byte
	err := tx.QueryRowContext(ctx, query, tenantID, integrationID).Scan(&projectID, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return MergeResult{}, false, nil
	}
	if err != nil {
		return MergeResult{}, false, err
	}
	audit, err := decodeConflictAudit(encoded)
	result := MergeResult{TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID, Audit: audit}
	if err != nil || !validConflictResult(result) {
		return MergeResult{}, false, ErrImmutable
	}
	return result, true, nil
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
	if pending {
		return result.Commit == ""
	}
	return commitID(result.Commit)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == strings.ToLower(value)
}

var _ Store = (*PostgresStore)(nil)
