package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

var submissionDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type PostgresSubmissionStore struct {
	database *sql.DB
}

func NewPostgresSubmissionStore(database *sql.DB) (*PostgresSubmissionStore, error) {
	if database == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresSubmissionStore{database: database}, nil
}

func (store *PostgresSubmissionStore) Get(ctx context.Context, tenantID, taskID, attemptSeriesID string, attempt int) (Submission, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !safeIDPattern.MatchString(tenantID) || !safeIDPattern.MatchString(taskID) || !safeIDPattern.MatchString(attemptSeriesID) || attempt < 1 || attempt > 3 {
		return Submission{}, false, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Submission{}, false, err
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return Submission{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	submission, found, err := loadPostgresSubmission(ctx, tx, tenantID, taskID, attemptSeriesID, attempt)
	if err != nil || !found {
		return Submission{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return Submission{}, false, err
	}
	return submission, true, nil
}

func (store *PostgresSubmissionStore) Put(ctx context.Context, submission Submission) error {
	if store == nil || store.database == nil || ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateStoredSubmission(submission); err != nil {
		return err
	}
	manifestJSON, err := json.Marshal(submission.Manifest)
	if err != nil {
		return ErrInvalidRequest
	}
	commitAt := submission.CommitAt.UTC()
	if commitAt.IsZero() {
		commitAt, err = time.Parse(time.RFC3339, submission.Manifest.CreatedAt)
		if err != nil {
			return ErrInvalidRequest
		}
	}
	workspace := submission.Workspace
	id, err := newSubmissionID()
	if err != nil {
		return err
	}
	tx, err := store.begin(ctx, workspace.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO submissions
  (id, tenant_id, project_id, module_task_id, attempt_series_id, attempt,
   base_commit, head_commit, schema_version, manifest_jsonb, manifest_sha256,
   created_by_agent_id, created_at, idempotency_key, request_sha256)
VALUES
  ($1, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7, $8, $9,
   $10::jsonb, $11, $12, $13, $14, $15)
ON CONFLICT DO NOTHING`, id, workspace.TenantID, workspace.ProjectID, workspace.TaskID,
		submission.Manifest.AttemptSeriesID, submission.Manifest.Attempt,
		submission.Manifest.BaseCommit, submission.Manifest.HeadCommit,
		submission.Manifest.SubmissionVersion, manifestJSON, submission.Manifest.SHA256,
		submission.Manifest.AgentIdentity.AgentInstanceID, commitAt,
		submission.IdempotencyKey, submission.RequestSHA256)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		prior, found, loadErr := loadPostgresSubmission(ctx, tx, workspace.TenantID, workspace.TaskID, submission.Manifest.AttemptSeriesID, submission.Manifest.Attempt)
		if loadErr != nil {
			return loadErr
		}
		if !found || prior.Manifest.SHA256 != submission.Manifest.SHA256 || prior.IdempotencyKey != submission.IdempotencyKey || prior.RequestSHA256 != submission.RequestSHA256 {
			return ErrSubmissionConflict
		}
	}
	return tx.Commit()
}

func newSubmissionID() (uuid.UUID, error) {
	return uuid.NewV7()
}

func (store *PostgresSubmissionStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if tenantID == "" {
		return nil, ErrInvalidRequest
	}
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
		return nil, ErrInvalidRequest
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func loadPostgresSubmission(ctx context.Context, tx *sql.Tx, tenantID, taskID, attemptSeriesID string, attempt int) (Submission, bool, error) {
	var manifestJSON []byte
	var commitAt time.Time
	var idempotencyKey, requestSHA256 string
	err := tx.QueryRowContext(ctx, `
SELECT manifest_jsonb, created_at, idempotency_key, request_sha256
FROM submissions
WHERE tenant_id = $1::uuid AND module_task_id = $2::uuid
  AND attempt_series_id = $3::uuid AND attempt = $4`, tenantID, taskID, attemptSeriesID, attempt).Scan(&manifestJSON, &commitAt, &idempotencyKey, &requestSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return Submission{}, false, nil
	}
	if err != nil {
		return Submission{}, false, err
	}
	var submission Submission
	if json.Unmarshal(manifestJSON, &submission.Manifest) != nil {
		return Submission{}, false, ErrInvalidRequest
	}
	submission.Workspace = Workspace{
		TenantID:        tenantID,
		ProjectID:       submission.Manifest.ProjectID,
		TaskID:          taskID,
		Attempt:         attempt,
		AttemptSeriesID: attemptSeriesID,
		BaseCommit:      submission.Manifest.BaseCommit,
		ModuleSpecRef:   submission.Manifest.ModuleSpecRef,
		AgentIdentity:   submission.Manifest.AgentIdentity,
	}
	submission.CommitAt = commitAt.UTC()
	submission.IdempotencyKey = idempotencyKey
	submission.RequestSHA256 = requestSHA256
	if err := validateStoredSubmission(submission); err != nil {
		return Submission{}, false, err
	}
	return submission, true, nil
}

func validateStoredSubmission(submission Submission) error {
	workspace := submission.Workspace
	manifest := submission.Manifest
	if !safeIDPattern.MatchString(workspace.TenantID) || !safeIDPattern.MatchString(workspace.ProjectID) || !safeIDPattern.MatchString(workspace.TaskID) || !safeIDPattern.MatchString(manifest.AttemptSeriesID) || !safeCommitMetadata(submission.IdempotencyKey) || !submissionDigestPattern.MatchString(submission.RequestSHA256) || manifest.ProjectID != workspace.ProjectID || manifest.ModuleTaskID != workspace.TaskID || manifest.AttemptSeriesID != workspace.AttemptSeriesID || manifest.Attempt != workspace.Attempt || manifest.BaseCommit != workspace.BaseCommit || manifest.ModuleSpecRef != workspace.ModuleSpecRef || manifest.AgentIdentity != workspace.AgentIdentity || !validServiceSignature(manifest.Signature) {
		return ErrInvalidRequest
	}
	if err := manifest.Validate(); err != nil {
		return ErrInvalidRequest
	}
	digest, err := DigestManifest(manifest)
	if err != nil || digest != manifest.SHA256 {
		return ErrInvalidRequest
	}
	return nil
}

var _ SubmissionStore = (*PostgresSubmissionStore)(nil)
