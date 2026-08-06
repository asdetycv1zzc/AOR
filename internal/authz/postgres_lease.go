package authz

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type PostgresLeaseStore struct {
	database *sql.DB
}

func NewPostgresLeaseStore(database *sql.DB) (*PostgresLeaseStore, error) {
	if database == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease database"})
	}
	return &PostgresLeaseStore{database: database}, nil
}

func (store *PostgresLeaseStore) Put(ctx context.Context, lease CapabilityLease) error {
	if store == nil || store.database == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if ctx == nil || ctx.Err() != nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := lease.ValidateShape(); err != nil {
		return err
	}
	resource, capabilities, err := encodeLeaseJSON(lease)
	if err != nil {
		return err
	}
	tx, err := store.begin(ctx, lease.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
	INSERT INTO agent_leases
	  (id, idempotency_key, tenant_id, project_id, agent_instance_id, task_id, principal_id, principal_type,
   role, action, project_version, task_version, spec_sha256, resource_jsonb,
   parameter_sha256, issued_at, expires_at, last_heartbeat_at,
   heartbeat_interval_seconds, capabilities_jsonb, policy_version, budget_account_id,
   nonce_hash, fencing_token, state, revoked_at, signature)
VALUES
	  ($1, NULLIF($2, ''), $3::uuid, $4::uuid, $5, NULLIF($6, '')::uuid, $7, $8, $9,
	   $10, $11, $12, $13, $14, $15::jsonb, $16, $17, $18, $19,
	   $20::jsonb, $21, $22, $23, $24, $25, $26, $27)`,
		lease.ID, lease.IdempotencyKey, lease.TenantID, lease.ProjectID, nullableLeaseAgentInstance(lease), nullableLeaseString(lease.TaskID),
		lease.PrincipalID, string(lease.PrincipalType), lease.Role, lease.Action,
		lease.ProjectVersion, lease.TaskVersion, nullableLeaseString(lease.SpecDigest), resource,
		lease.ParameterDigest, lease.IssuedAt.UTC(), lease.ExpiresAt.UTC(),
		lease.LastHeartbeatAt.UTC(), lease.HeartbeatIntervalSeconds, capabilities,
		lease.PolicyVersion, lease.BudgetAccountID, lease.Nonce, lease.FencingToken,
		string(lease.State), nullableLeaseTime(lease.RevokedAt), lease.Signature,
	)
	if err != nil {
		return mapLeaseSQLError(err)
	}
	if err := advanceTaskFencing(ctx, tx, lease); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (store *PostgresLeaseStore) Get(ctx context.Context, id string) (CapabilityLease, bool, error) {
	if store == nil || store.database == nil || ctx == nil || id == "" {
		return CapabilityLease{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease lookup"})
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, false, err
	}
	tenantID := leaseTenantID(ctx)
	if tenantID == "" {
		return CapabilityLease{}, false, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease tenant"})
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return CapabilityLease{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	lease, found, err := loadPostgresLease(ctx, tx, tenantID, id, false)
	if err != nil || !found {
		return CapabilityLease{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return CapabilityLease{}, false, err
	}
	return lease, true, nil
}

func (store *PostgresLeaseStore) CompareAndSwap(ctx context.Context, id string, expected int64, replacement CapabilityLease) (bool, error) {
	if store == nil || store.database == nil || ctx == nil || id == "" || expected < 1 || replacement.ID != id {
		return false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease compare and swap"})
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := replacement.ValidateShape(); err != nil {
		return false, err
	}
	tx, err := store.begin(ctx, replacement.TenantID, false)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	current, found, err := loadPostgresLease(ctx, tx, replacement.TenantID, id, true)
	if err != nil {
		return false, err
	}
	if !found || current.FencingToken != expected || !sameLeaseBinding(current, replacement) {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE agent_leases
SET expires_at = $4, last_heartbeat_at = $5, fencing_token = $6, state = $7,
    revoked_at = $8, nonce_hash = $9, signature = $10
WHERE tenant_id = $1::uuid AND id = $2 AND fencing_token = $3`,
		replacement.TenantID, id, expected, replacement.ExpiresAt.UTC(),
		replacement.LastHeartbeatAt.UTC(), replacement.FencingToken,
		string(replacement.State), nullableLeaseTime(replacement.RevokedAt),
		replacement.Nonce, replacement.Signature)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows != 1 {
		return false, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "lease fencing"})
	}
	if err := advanceTaskFencing(ctx, tx, replacement); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (store *PostgresLeaseStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease tenant"})
	}
	options := &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly}
	tx, err := store.database.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := setLeaseTenant(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func setLeaseTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	var superuser bool
	var bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		return err
	}
	if superuser || bypassRLS {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "database role bypasses tenant isolation"})
	}
	_, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID)
	return err
}

func loadPostgresLease(ctx context.Context, tx *sql.Tx, tenantID, id string, lock bool) (CapabilityLease, bool, error) {
	query := `
	SELECT id, COALESCE(agent_instance_id, principal_id), principal_id, principal_type, tenant_id::text,
	       idempotency_key, project_id::text, project_version, COALESCE(task_id::text, ''), task_version,
	       COALESCE(spec_sha256::text, ''),
       role, action, resource_jsonb, parameter_sha256, capabilities_jsonb, issued_at,
       expires_at, last_heartbeat_at, heartbeat_interval_seconds, policy_version,
       budget_account_id, nonce_hash, fencing_token, state, revoked_at, signature
FROM agent_leases
WHERE tenant_id = $1::uuid AND id = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	lease, err := scanPostgresLease(tx.QueryRowContext(ctx, query, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return CapabilityLease{}, false, nil
	}
	if err != nil {
		return CapabilityLease{}, false, err
	}
	return lease, true, nil
}

func (store *PostgresLeaseStore) GetByIdempotency(ctx context.Context, tenantID, principalID, key string) (CapabilityLease, bool, error) {
	if store == nil || store.database == nil || ctx == nil || tenantID == "" || principalID == "" || key == "" {
		return CapabilityLease{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, false, err
	}
	if scopedTenant := leaseTenantID(ctx); scopedTenant != "" && scopedTenant != tenantID {
		return CapabilityLease{}, false, nil
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return CapabilityLease{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	lease, found, err := loadPostgresLeaseByIdempotency(ctx, tx, tenantID, principalID, key)
	if err != nil || !found {
		return CapabilityLease{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return CapabilityLease{}, false, err
	}
	return lease, true, nil
}

func loadPostgresLeaseByIdempotency(ctx context.Context, tx *sql.Tx, tenantID, principalID, key string) (CapabilityLease, bool, error) {
	lease, err := scanPostgresLease(tx.QueryRowContext(ctx, `
SELECT id, COALESCE(agent_instance_id, principal_id), principal_id, principal_type, tenant_id::text,
       idempotency_key, project_id::text, project_version, COALESCE(task_id::text, ''), task_version,
       COALESCE(spec_sha256::text, ''), role, action, resource_jsonb, parameter_sha256, capabilities_jsonb, issued_at,
       expires_at, last_heartbeat_at, heartbeat_interval_seconds, policy_version,
       budget_account_id, nonce_hash, fencing_token, state, revoked_at, signature
FROM agent_leases
WHERE tenant_id = $1::uuid AND principal_id = $2 AND idempotency_key = $3`, tenantID, principalID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return CapabilityLease{}, false, nil
	}
	if err != nil {
		return CapabilityLease{}, false, err
	}
	return lease, true, nil
}

type leaseRowScanner interface {
	Scan(...any) error
}

func scanPostgresLease(scanner leaseRowScanner) (CapabilityLease, error) {
	var lease CapabilityLease
	var idempotencyKey sql.NullString
	var principalType string
	var state string
	var resource []byte
	var capabilities []byte
	var revokedAt sql.NullTime
	err := scanner.Scan(
		&lease.ID, &lease.AgentInstanceID, &lease.PrincipalID, &principalType,
		&lease.TenantID, &idempotencyKey, &lease.ProjectID, &lease.ProjectVersion, &lease.TaskID,
		&lease.TaskVersion, &lease.SpecDigest, &lease.Role, &lease.Action, &resource,
		&lease.ParameterDigest, &capabilities, &lease.IssuedAt, &lease.ExpiresAt,
		&lease.LastHeartbeatAt, &lease.HeartbeatIntervalSeconds, &lease.PolicyVersion,
		&lease.BudgetAccountID, &lease.Nonce, &lease.FencingToken, &state, &revokedAt,
		&lease.Signature,
	)
	if err != nil {
		return CapabilityLease{}, err
	}
	lease.PrincipalType = authn.PrincipalType(principalType)
	lease.IdempotencyKey = idempotencyKey.String
	lease.State = LeaseState(state)
	lease.IssuedAt = lease.IssuedAt.UTC()
	lease.ExpiresAt = lease.ExpiresAt.UTC()
	lease.LastHeartbeatAt = lease.LastHeartbeatAt.UTC()
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		lease.RevokedAt = &value
	}
	if err := json.Unmarshal(resource, &lease.Resource); err != nil {
		return CapabilityLease{}, err
	}
	if err := json.Unmarshal(capabilities, &lease.Capabilities); err != nil {
		return CapabilityLease{}, err
	}
	if err := lease.ValidateShape(); err != nil {
		return CapabilityLease{}, err
	}
	return lease, nil
}

func encodeLeaseJSON(lease CapabilityLease) ([]byte, []byte, error) {
	resource, err := json.Marshal(lease.Resource)
	if err != nil {
		return nil, nil, err
	}
	capabilities, err := json.Marshal(lease.Capabilities)
	if err != nil {
		return nil, nil, err
	}
	return resource, capabilities, nil
}

func sameLeaseBinding(current, replacement CapabilityLease) bool {
	current.ExpiresAt = replacement.ExpiresAt
	current.LastHeartbeatAt = replacement.LastHeartbeatAt
	current.FencingToken = replacement.FencingToken
	current.State = replacement.State
	current.RevokedAt = cloneTimePointer(replacement.RevokedAt)
	current.Nonce = replacement.Nonce
	current.Signature = replacement.Signature
	return reflect.DeepEqual(current, replacement)
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func nullableLeaseTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func nullableLeaseString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableLeaseAgentInstance(lease CapabilityLease) any {
	if lease.PrincipalType == authn.PrincipalService {
		return nil
	}
	return lease.AgentInstanceID
}

func advanceTaskFencing(ctx context.Context, tx *sql.Tx, lease CapabilityLease) error {
	if lease.TaskID == "" || !IsSideEffect(lease.Action) {
		return nil
	}
	var advanced sql.NullBool
	err := tx.QueryRowContext(ctx, `
SELECT aor_advance_task_fencing($1::uuid, $2::uuid, $3::uuid, $4)`,
		lease.TenantID, lease.ProjectID, lease.TaskID, lease.FencingToken).Scan(&advanced)
	if err != nil {
		return err
	}
	if !advanced.Valid || !advanced.Bool {
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "task fencing"})
	}
	return nil
}

type leaseSQLStateError interface {
	SQLState() string
}

func mapLeaseSQLError(err error) error {
	var state leaseSQLStateError
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "lease"})
	}
	return err
}

var _ LeaseStore = (*PostgresLeaseStore)(nil)
