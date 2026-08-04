package workflow

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type PostgresActivityResultStore struct {
	database *sql.DB
}

func NewPostgresActivityResultStore(database *sql.DB) (*PostgresActivityResultStore, error) {
	if database == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity result database"})
	}
	return &PostgresActivityResultStore{database: database}, nil
}

func (store *PostgresActivityResultStore) Load(ctx context.Context, tenantID, key, requestSHA256 string) (json.RawMessage, bool, error) {
	if store == nil || store.database == nil {
		return nil, false, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := activityStoreContext(ctx, tenantID, key, requestSHA256); err != nil {
		return nil, false, err
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	output, found, err := loadActivityResult(ctx, tx, tenantID, key, requestSHA256)
	if err != nil || !found {
		return nil, found, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return output, true, nil
}

func (store *PostgresActivityResultStore) Save(ctx context.Context, tenantID, key, requestSHA256 string, output json.RawMessage) error {
	if store == nil || store.database == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := activityStoreContext(ctx, tenantID, key, requestSHA256); err != nil {
		return err
	}
	if !json.Valid(output) || len(output) > MaximumActivityResultBytes {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity result"})
	}
	digest, err := canonicaljson.Digest(output)
	if err != nil {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity result"})
	}
	tx, err := store.begin(ctx, tenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO workflow_activity_results
  (tenant_id, idempotency_key, request_sha256, output_jsonb, output_sha256)
VALUES ($1::uuid, $2, $3, $4::jsonb, $5)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`, tenantID, key, requestSHA256, []byte(output), digest)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		stored, found, loadErr := loadActivityResult(ctx, tx, tenantID, key, requestSHA256)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "activity result"})
		}
		storedDigest, digestErr := canonicaljson.Digest(stored)
		if digestErr != nil || storedDigest != digest {
			return aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
		}
	}
	return tx.Commit()
}

func (store *PostgresActivityResultStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	options := &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly}
	tx, err := store.database.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func loadActivityResult(ctx context.Context, tx *sql.Tx, tenantID, key, requestSHA256 string) (json.RawMessage, bool, error) {
	var storedRequest, storedDigest string
	var output []byte
	err := tx.QueryRowContext(ctx, `
SELECT request_sha256, output_jsonb, output_sha256
FROM workflow_activity_results
WHERE tenant_id = $1::uuid AND idempotency_key = $2`, tenantID, key).Scan(&storedRequest, &output, &storedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if storedRequest != requestSHA256 {
		return nil, false, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	}
	digest, err := canonicaljson.Digest(output)
	if err != nil || digest != storedDigest {
		return nil, false, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "activity result"})
	}
	return append(json.RawMessage(nil), output...), true, nil
}

var _ ActivityResultStore = (*PostgresActivityResultStore)(nil)
