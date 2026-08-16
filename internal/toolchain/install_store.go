package toolchain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

type InstallationState string

const (
	InstallationQueued     InstallationState = "QUEUED"
	InstallationInstalling InstallationState = "INSTALLING"
	InstallationInstalled  InstallationState = "INSTALLED"
	InstallationFailed     InstallationState = "FAILED"
)

const maxInstallationAttempts = 5

type Installation struct {
	ID               string
	TenantID         string
	ProjectID        string
	GoalSpecID       string
	GoalVersion      int
	ToolKey          string
	Tool             contracts.VersionedTool
	State            InstallationState
	Attempt          int
	AvailableAt      time.Time
	LeaseToken       string
	LeaseExpiresAt   *time.Time
	InventoryID      string
	LastErrorCode    string
	LastErrorMessage string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	FinishedAt       *time.Time
}

type InstallationBatch struct {
	ID              string
	TenantID        string
	ProjectID       string
	GoalSpecID      string
	GoalVersion     int
	MessageID       string
	Principal       authn.Principal
	State           string
	RecoveryAttempt int
	LeaseExpiresAt  *time.Time
}

type InstallStore struct {
	db *sql.DB
}

func NewInstallStore(db *sql.DB) (*InstallStore, error) {
	if db == nil {
		return nil, errors.New("toolchain installation database is required")
	}
	return &InstallStore{db: db}, nil
}

// Schedule records every provisionable archive in the GoalSpec. Repeating the
// call for the same immutable goal and tool is a no-op.
func (store *InstallStore) Schedule(ctx context.Context, tenantID, projectID, goalSpecID string, goalVersion int, messageID string, principal authn.Principal, tools []contracts.VersionedTool, now time.Time) ([]Installation, error) {
	if store == nil || ctx == nil || tenantID == "" || projectID == "" || goalSpecID == "" || goalVersion < 1 || !validInstallToken(messageID, 256) || principal.ID == "" || principal.TenantID != tenantID || principal.Role == "" || principal.Type != authn.PrincipalUser && principal.Type != authn.PrincipalBreakGlassAdmin || now.IsZero() {
		return nil, errors.New("invalid toolchain installation schedule")
	}
	ready := make([]scheduledTool, 0, len(tools))
	for _, tool := range tools {
		if !tool.ReadyToProvision() {
			continue
		}
		if tool.Install == nil || !SupportsProvisionableArchive(tool) {
			return nil, ErrUnsupportedTool
		}
		raw, err := json.Marshal(tool)
		if err != nil {
			return nil, fmt.Errorf("encode toolchain installation: %w", err)
		}
		encoded, err := canonicaljson.Canonicalize(raw)
		if err != nil {
			return nil, fmt.Errorf("canonicalize toolchain installation: %w", err)
		}
		key, err := canonicaljson.Digest(encoded)
		if err != nil {
			return nil, fmt.Errorf("digest toolchain installation: %w", err)
		}
		ready = append(ready, scheduledTool{encoded: encoded, key: key})
	}
	if len(ready) == 0 {
		return []Installation{}, nil
	}

	var installations []Installation
	err := store.withTenantTx(ctx, tenantID, false, func(tx *sql.Tx) error {
		batchID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var durableBatchID, durableMessageID, durablePrincipalID, durablePrincipalType, durablePrincipalRole string
		if err := tx.QueryRowContext(ctx, `
WITH scheduled AS (
  INSERT INTO toolchain_installation_batches (
    id, tenant_id, project_id, goal_spec_id, goal_version, message_id,
    principal_id, principal_type, principal_role, state, recovery_attempt,
    recovery_available_at, created_at, updated_at
  ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9,
            'WAITING', 0, $10, $10, $10)
  ON CONFLICT (tenant_id, project_id, goal_spec_id, goal_version) DO NOTHING
  RETURNING id, message_id, principal_id, principal_type, principal_role
)
SELECT id::text, message_id, principal_id, principal_type, principal_role
FROM scheduled
UNION ALL
SELECT id::text, message_id, principal_id, principal_type, principal_role
FROM toolchain_installation_batches
WHERE tenant_id = $2::uuid AND project_id = $3::uuid
  AND goal_spec_id = $4::uuid AND goal_version = $5
LIMIT 1`, batchID.String(), tenantID, projectID, goalSpecID, goalVersion, messageID, principal.ID, principal.Type, principal.Role, now.UTC()).Scan(&durableBatchID, &durableMessageID, &durablePrincipalID, &durablePrincipalType, &durablePrincipalRole); err != nil {
			return err
		}
		if durableMessageID != messageID || durablePrincipalID != principal.ID || durablePrincipalType != string(principal.Type) || durablePrincipalRole != principal.Role {
			return errors.New("toolchain installation batch already belongs to different recovery metadata")
		}
		for _, candidate := range ready {
			installationID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			row := tx.QueryRowContext(ctx, `
WITH scheduled AS (
  INSERT INTO toolchain_installations (
    id, tenant_id, batch_id, project_id, goal_spec_id, goal_version, tool_key, tool_jsonb,
    state, attempt, available_at, created_at, updated_at
  ) VALUES (
    $1::uuid, $2::uuid, $9::uuid, $3::uuid, $4::uuid, $5, $6, $7::jsonb,
    'QUEUED', 0, $8, $8, $8
  )
	  ON CONFLICT (tenant_id, project_id, goal_spec_id, goal_version, tool_key) DO NOTHING
  RETURNING *
)
SELECT id::text, tenant_id::text, project_id::text, goal_spec_id::text,
       goal_version, tool_key, tool_jsonb, state, attempt, available_at,
       COALESCE(lease_token, ''), lease_expires_at, COALESCE(inventory_id, ''),
       COALESCE(last_error_code, ''), COALESCE(last_error_message, ''),
       created_at, updated_at, finished_at
FROM scheduled
UNION ALL
SELECT id::text, tenant_id::text, project_id::text, goal_spec_id::text,
       goal_version, tool_key, tool_jsonb, state, attempt, available_at,
       COALESCE(lease_token, ''), lease_expires_at, COALESCE(inventory_id, ''),
       COALESCE(last_error_code, ''), COALESCE(last_error_message, ''),
       created_at, updated_at, finished_at
FROM toolchain_installations
	WHERE tenant_id = $2::uuid AND project_id = $3::uuid
	  AND goal_spec_id = $4::uuid AND goal_version = $5 AND tool_key = $6
LIMIT 1`, installationID.String(), tenantID, projectID, goalSpecID, goalVersion, candidate.key, candidate.encoded, now.UTC(), durableBatchID)
			installation, err := scanInstallation(row)
			if err != nil {
				return err
			}
			installations = append(installations, installation)
		}
		return nil
	})
	return installations, err
}

// ClaimQueued leases work across all tenants through the migration's
// SECURITY DEFINER function. Expired leases are retried up to five attempts.
func (store *InstallStore) ClaimQueued(ctx context.Context, limit int, leaseToken string, leaseDuration time.Duration) ([]Installation, error) {
	if store == nil || ctx == nil || limit < 1 || limit > 16 || !validInstallToken(leaseToken, 256) || leaseDuration < 30*time.Second || leaseDuration > time.Hour || leaseDuration%time.Second != 0 {
		return nil, errors.New("invalid toolchain installation claim")
	}
	if _, err := store.db.ExecContext(ctx, `SELECT aor_expire_toolchain_installation_leases()`); err != nil {
		return nil, err
	}
	rows, err := store.db.QueryContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, goal_spec_id::text,
       goal_version, tool_key, tool_jsonb, state, attempt, available_at,
       COALESCE(lease_token, ''), lease_expires_at, COALESCE(inventory_id, ''),
       COALESCE(last_error_code, ''), COALESCE(last_error_message, ''),
       created_at, updated_at, finished_at
FROM aor_claim_toolchain_installations($1, $2, $3)`, limit, leaseToken, int(leaseDuration/time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	installations := make([]Installation, 0, limit)
	for rows.Next() {
		installation, scanErr := scanInstallation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		installations = append(installations, installation)
	}
	return installations, rows.Err()
}

func (store *InstallStore) ExtendClaim(ctx context.Context, installationID, leaseToken string, attempt int, leaseDuration time.Duration) error {
	if store == nil || ctx == nil || installationID == "" || !validInstallToken(leaseToken, 256) || attempt < 1 || attempt > maxInstallationAttempts || leaseDuration < 30*time.Second || leaseDuration > time.Hour || leaseDuration%time.Second != 0 {
		return errors.New("invalid toolchain installation lease extension")
	}
	var extended bool
	if err := store.db.QueryRowContext(ctx, `SELECT aor_extend_toolchain_installation_lease($1::uuid, $2, $3, $4)`, installationID, leaseToken, attempt, int(leaseDuration/time.Second)).Scan(&extended); err != nil {
		return err
	}
	if !extended {
		return errors.New("toolchain installation lease is no longer current")
	}
	return nil
}

func (store *InstallStore) Complete(ctx context.Context, installationID, leaseToken, inventoryID string, attempt int, now time.Time) error {
	if store == nil || ctx == nil || installationID == "" || !validInstallToken(leaseToken, 256) || !validInstallToken(inventoryID, 128) || attempt < 1 || attempt > maxInstallationAttempts || now.IsZero() {
		return errors.New("invalid toolchain installation completion")
	}
	return store.updateClaimed(ctx, installationID, leaseToken, attempt, func(tx *sql.Tx, tenantID string) error {
		result, err := tx.ExecContext(ctx, `
UPDATE toolchain_installations
SET state = 'INSTALLED', inventory_id = $4, lease_token = NULL,
    lease_expires_at = NULL, claimed_attempt = NULL, last_error_code = NULL,
    last_error_message = NULL, updated_at = $5, finished_at = $5
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'INSTALLING'
  AND lease_token = $3 AND claimed_attempt = $6`, tenantID, installationID, leaseToken, inventoryID, now.UTC(), attempt)
		return requireInstallationUpdate(result, err)
	})
}

func (store *InstallStore) Fail(ctx context.Context, installationID, leaseToken string, attempt int, retry bool, errorCode, errorMessage string, now time.Time) error {
	if store == nil || ctx == nil || installationID == "" || !validInstallToken(leaseToken, 256) || attempt < 1 || attempt > maxInstallationAttempts || !validErrorValue(errorCode, 128) || !validErrorValue(errorMessage, 4096) || now.IsZero() {
		return errors.New("invalid toolchain installation failure")
	}
	requeue := retry && attempt < maxInstallationAttempts
	state := InstallationFailed
	var availableAt, finishedAt any = now.UTC(), now.UTC()
	if requeue {
		state = InstallationQueued
		availableAt = now.UTC().Add(retryDelay(attempt))
		finishedAt = nil
	}
	return store.updateClaimed(ctx, installationID, leaseToken, attempt, func(tx *sql.Tx, tenantID string) error {
		result, err := tx.ExecContext(ctx, `
UPDATE toolchain_installations
SET state = $5, available_at = $6, lease_token = NULL, lease_expires_at = NULL,
    claimed_attempt = NULL, last_error_code = $7, last_error_message = $8,
    updated_at = $9, finished_at = $10
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'INSTALLING'
  AND lease_token = $3 AND claimed_attempt = $4`, tenantID, installationID, leaseToken, attempt, state, availableAt, errorCode, errorMessage, now.UTC(), finishedAt)
		return requireInstallationUpdate(result, err)
	})
}

// ForGoal returns all scheduled installations and whether every one has
// reached INSTALLED. No rows is not considered complete.
func (store *InstallStore) ForGoal(ctx context.Context, tenantID, projectID, goalSpecID string, goalVersion int) ([]Installation, bool, error) {
	if store == nil || ctx == nil || tenantID == "" || projectID == "" || goalSpecID == "" || goalVersion < 1 {
		return nil, false, errors.New("invalid toolchain installation goal scope")
	}
	var installations []Installation
	err := store.withTenantTx(ctx, tenantID, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, goal_spec_id::text,
       goal_version, tool_key, tool_jsonb, state, attempt, available_at,
       COALESCE(lease_token, ''), lease_expires_at, COALESCE(inventory_id, ''),
       COALESCE(last_error_code, ''), COALESCE(last_error_message, ''),
       created_at, updated_at, finished_at
FROM toolchain_installations
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
  AND goal_spec_id = $3::uuid AND goal_version = $4
ORDER BY created_at, id`, tenantID, projectID, goalSpecID, goalVersion)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			installation, scanErr := scanInstallation(rows)
			if scanErr != nil {
				return scanErr
			}
			installations = append(installations, installation)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	allInstalled := len(installations) > 0
	for _, installation := range installations {
		allInstalled = allInstalled && installation.State == InstallationInstalled
	}
	return installations, allInstalled, nil
}

func (store *InstallStore) ClaimReadyBatches(ctx context.Context, limit int, leaseToken string, leaseDuration time.Duration) ([]InstallationBatch, error) {
	if store == nil || ctx == nil || limit < 1 || limit > 16 || !validInstallToken(leaseToken, 256) || leaseDuration < 30*time.Second || leaseDuration > time.Hour || leaseDuration%time.Second != 0 {
		return nil, errors.New("invalid toolchain installation recovery claim")
	}
	if _, err := store.db.ExecContext(ctx, `SELECT aor_reconcile_toolchain_installation_batches()`); err != nil {
		return nil, err
	}
	if _, err := store.db.ExecContext(ctx, `SELECT aor_expire_toolchain_installation_batch_leases()`); err != nil {
		return nil, err
	}
	rows, err := store.db.QueryContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, goal_spec_id::text,
       goal_version, message_id, principal_id, principal_type, principal_role,
       recovery_attempt, recovery_lease_expires_at
FROM aor_claim_ready_toolchain_installation_batches($1, $2, $3)`, limit, leaseToken, int(leaseDuration/time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	batches := make([]InstallationBatch, 0, limit)
	for rows.Next() {
		batch, scanErr := scanInstallationBatch(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		batch.State = "RECOVERING"
		batches = append(batches, batch)
	}
	return batches, rows.Err()
}

func (store *InstallStore) CompleteBatch(ctx context.Context, batchID, leaseToken string, attempt int) error {
	return store.finishBatch(ctx, batchID, leaseToken, attempt, true, false, "", "")
}

func (store *InstallStore) FailBatch(ctx context.Context, batchID, leaseToken string, attempt int, retry bool, errorCode, errorMessage string) error {
	if !validErrorValue(errorCode, 128) || !validErrorValue(errorMessage, 4096) {
		return errors.New("invalid toolchain installation recovery failure")
	}
	return store.finishBatch(ctx, batchID, leaseToken, attempt, false, retry, errorCode, errorMessage)
}

func (store *InstallStore) finishBatch(ctx context.Context, batchID, leaseToken string, attempt int, succeeded, retry bool, errorCode, errorMessage string) error {
	if store == nil || ctx == nil || batchID == "" || !validInstallToken(leaseToken, 256) || attempt < 1 || attempt > maxInstallationAttempts {
		return errors.New("invalid toolchain installation recovery completion")
	}
	var updated bool
	if err := store.db.QueryRowContext(ctx, `SELECT aor_finish_toolchain_installation_batch($1::uuid, $2, $3, $4, $5, $6, $7)`, batchID, leaseToken, attempt, succeeded, retry, nullableError(errorCode), nullableError(errorMessage)).Scan(&updated); err != nil {
		return err
	}
	if !updated {
		return errors.New("toolchain installation recovery lease is no longer current")
	}
	return nil
}

func (store *InstallStore) ListProjectBatches(ctx context.Context, tenantID, projectID string) ([]InstallationBatch, error) {
	if store == nil || ctx == nil || tenantID == "" || projectID == "" {
		return nil, errors.New("invalid toolchain installation project scope")
	}
	var batches []InstallationBatch
	err := store.withTenantTx(ctx, tenantID, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, goal_spec_id::text,
       goal_version, message_id, principal_id, principal_type, principal_role,
       recovery_attempt, recovery_lease_expires_at, state
FROM toolchain_installation_batches
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
ORDER BY created_at, id`, tenantID, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			batch, scanErr := scanInstallationBatchWithState(rows)
			if scanErr != nil {
				return scanErr
			}
			batches = append(batches, batch)
		}
		return rows.Err()
	})
	return batches, err
}

func (store *InstallStore) ReconciliationTenants(ctx context.Context, limit int) ([]string, error) {
	if store == nil || ctx == nil || limit < 1 || limit > 1000 {
		return nil, errors.New("invalid toolchain reconciliation tenant query")
	}
	rows, err := store.db.QueryContext(ctx, `
SELECT tenant_id::text
FROM aor_toolchain_schedule_reconciliation_tenants($1)`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tenantIDs := make([]string, 0, limit)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	return tenantIDs, rows.Err()
}

type scheduledTool struct {
	encoded []byte
	key     string
}

type installationScanner interface {
	Scan(...any) error
}

func scanInstallationBatch(row installationScanner) (InstallationBatch, error) {
	var batch InstallationBatch
	if err := row.Scan(&batch.ID, &batch.TenantID, &batch.ProjectID, &batch.GoalSpecID,
		&batch.GoalVersion, &batch.MessageID, &batch.Principal.ID, &batch.Principal.Type,
		&batch.Principal.Role, &batch.RecoveryAttempt, &batch.LeaseExpiresAt); err != nil {
		return InstallationBatch{}, err
	}
	batch.Principal.TenantID = batch.TenantID
	batch.Principal.ProjectID = batch.ProjectID
	return batch, nil
}

func scanInstallationBatchWithState(row installationScanner) (InstallationBatch, error) {
	var batch InstallationBatch
	if err := row.Scan(&batch.ID, &batch.TenantID, &batch.ProjectID, &batch.GoalSpecID,
		&batch.GoalVersion, &batch.MessageID, &batch.Principal.ID, &batch.Principal.Type,
		&batch.Principal.Role, &batch.RecoveryAttempt, &batch.LeaseExpiresAt, &batch.State); err != nil {
		return InstallationBatch{}, err
	}
	batch.Principal.TenantID = batch.TenantID
	batch.Principal.ProjectID = batch.ProjectID
	return batch, nil
}

func scanInstallation(row installationScanner) (Installation, error) {
	var installation Installation
	var toolJSON []byte
	if err := row.Scan(
		&installation.ID, &installation.TenantID, &installation.ProjectID,
		&installation.GoalSpecID, &installation.GoalVersion, &installation.ToolKey,
		&toolJSON, &installation.State, &installation.Attempt, &installation.AvailableAt,
		&installation.LeaseToken, &installation.LeaseExpiresAt, &installation.InventoryID,
		&installation.LastErrorCode, &installation.LastErrorMessage, &installation.CreatedAt,
		&installation.UpdatedAt, &installation.FinishedAt,
	); err != nil {
		return Installation{}, err
	}
	if err := json.Unmarshal(toolJSON, &installation.Tool); err != nil {
		return Installation{}, fmt.Errorf("decode toolchain installation: %w", err)
	}
	return installation, nil
}

func (store *InstallStore) withTenantTx(ctx context.Context, tenantID string, readOnly bool, operation func(*sql.Tx) error) error {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: readOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *InstallStore) updateClaimed(ctx context.Context, installationID, leaseToken string, attempt int, operation func(*sql.Tx, string) error) error {
	var tenantID string
	if err := store.db.QueryRowContext(ctx, `
SELECT tenant_id::text
FROM aor_claimed_toolchain_installation($1::uuid, $2, $3)`, installationID, leaseToken, attempt).Scan(&tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("toolchain installation lease is no longer current")
		}
		return err
	}
	return store.withTenantTx(ctx, tenantID, false, func(tx *sql.Tx) error {
		return operation(tx, tenantID)
	})
}

func requireInstallationUpdate(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("toolchain installation lease is no longer current")
	}
	return nil
}

func retryDelay(attempt int) time.Duration {
	delay := time.Duration(1<<uint(attempt-1)) * 5 * time.Second
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

func validInstallToken(value string, limit int) bool {
	if len(value) < 1 || len(value) > limit || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for index, character := range value {
		alphanumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		punctuation := index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')
		if alphanumeric || punctuation {
			continue
		}
		return false
	}
	return true
}

func validErrorValue(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsAny(value, "\x00")
}

func nullableError(value string) any {
	if value == "" {
		return nil
	}
	return value
}
