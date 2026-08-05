package modelgateway

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type PostgresBudgetLedger struct {
	db             *sql.DB
	clock          func() time.Time
	reservationTTL time.Duration
	replay         *postgresReplayCodec
}

func NewPostgresBudgetLedger(db *sql.DB, clock func() time.Time, reservationTTL time.Duration) (*PostgresBudgetLedger, error) {
	return newPostgresBudgetLedger(db, clock, reservationTTL, nil)
}

func NewPostgresBudgetLedgerWithReplay(db *sql.DB, clock func() time.Time, reservationTTL time.Duration, replayConfig ReplayStoreConfig) (*PostgresBudgetLedger, error) {
	replay, err := newPostgresReplayCodec(replayConfig)
	if err != nil {
		return nil, err
	}
	return newPostgresBudgetLedger(db, clock, reservationTTL, replay)
}

func newPostgresBudgetLedger(db *sql.DB, clock func() time.Time, reservationTTL time.Duration, replay *postgresReplayCodec) (*PostgresBudgetLedger, error) {
	if db == nil || reservationTTL < 0 {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	if reservationTTL == 0 {
		reservationTTL = defaultReservationTTL
	}
	return &PostgresBudgetLedger{db: db, clock: clock, reservationTTL: reservationTTL, replay: replay}, nil
}

func (ledger *PostgresBudgetLedger) CreateAccount(ctx context.Context, account BudgetAccount) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if account.ID == "" || account.TenantID == "" || account.LimitMicros < 0 || account.SoftLimitMicros < 0 || account.SoftLimitMicros > account.LimitMicros || account.ReservedMicros < 0 || account.SpentMicros < 0 || account.ReservedMicros > account.LimitMicros-account.SpentMicros {
		return ErrInvalidRequest
	}
	if account.ScopeType == "" {
		account.ScopeType = "PROJECT"
	}
	if account.ScopeID == "" {
		account.ScopeID = account.ID
	}
	if account.Currency == "" {
		account.Currency = "USD"
	}
	if account.PeriodStart.IsZero() {
		account.PeriodStart = ledger.clock().UTC()
	}
	tx, err := ledger.begin(ctx, account.TenantID)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
INSERT INTO budget_accounts
  (tenant_id, id, scope_type, scope_id, currency, hard_limit_micros, soft_limit_micros,
   spent_micros, reserved_micros, period_start, period_end, version)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1)`,
		account.TenantID, account.ID, account.ScopeType, account.ScopeID, account.Currency, account.LimitMicros, account.SoftLimitMicros, account.SpentMicros, account.ReservedMicros, account.PeriodStart, account.PeriodEnd)
	if err != nil {
		return mapBudgetSQLError(err)
	}
	return tx.Commit()
}

func (ledger *PostgresBudgetLedger) Reserve(ctx context.Context, tenantID, accountID, reservationID, requestID string, amountMicros int64) (Reservation, error) {
	reservation, _, err := ledger.reserve(ctx, tenantID, accountID, reservationID, requestID, amountMicros, false)
	return reservation, err
}

func (ledger *PostgresBudgetLedger) ClaimReservation(ctx context.Context, tenantID, accountID, reservationID, requestID string, amountMicros int64) (Reservation, bool, error) {
	return ledger.reserve(ctx, tenantID, accountID, reservationID, requestID, amountMicros, true)
}

func (ledger *PostgresBudgetLedger) reserve(ctx context.Context, tenantID, accountID, reservationID, requestID string, amountMicros int64, claim bool) (Reservation, bool, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, false, err
	}
	if tenantID == "" || accountID == "" || reservationID == "" || requestID == "" || amountMicros < 0 {
		return Reservation{}, false, ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, tenantID)
	if err != nil {
		return Reservation{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	existing, found, err := loadBudgetReservation(ctx, tx, tenantID, reservationID, true)
	if err != nil {
		return Reservation{}, false, err
	}
	if found {
		if existing.State == ReservationOpen && !ledger.clock().UTC().Before(existing.ExpiresAt) {
			result, updateErr := tx.ExecContext(ctx, `
UPDATE budget_reservations SET state = 'RECONCILE', updated_at = $3
	WHERE tenant_id = $1::uuid AND id = $2 AND state = 'RESERVED'`, tenantID, existing.ID, ledger.clock().UTC())
			if updateErr != nil {
				return Reservation{}, false, updateErr
			}
			if updateErr = requireOneRow(result); updateErr != nil {
				return Reservation{}, false, updateErr
			}
			if updateErr = tx.Commit(); updateErr != nil {
				return Reservation{}, false, updateErr
			}
			return Reservation{}, false, ErrReconciliationRequired
		}
		if existing.AccountID == accountID && existing.RequestID == requestID && existing.ReservedMicros == amountMicros && existing.State == ReservationOpen {
			if err := tx.Commit(); err != nil {
				return Reservation{}, false, err
			}
			return existing, !claim, nil
		}
		if existing.State == ReservationReconcile {
			return Reservation{}, false, ErrReconciliationRequired
		}
		return Reservation{}, false, ErrReservationConflict
	}
	if claim {
		existing, found, err = loadBudgetReservationByRequest(ctx, tx, tenantID, requestID, true)
		if err != nil {
			return Reservation{}, false, err
		}
		if found {
			if existing.State == ReservationReconcile || existing.State == ReservationOpen && !ledger.clock().UTC().Before(existing.ExpiresAt) {
				return Reservation{}, false, ErrReconciliationRequired
			}
			return Reservation{}, false, ErrRequestConflict
		}
	}
	account, found, err := loadBudgetAccount(ctx, tx, tenantID, accountID, true)
	if err != nil {
		return Reservation{}, false, err
	}
	if !found || !budgetPeriodOpen(ledger.clock().UTC(), account) || amountMicros > account.LimitMicros-account.ReservedMicros-account.SpentMicros {
		return Reservation{}, false, ErrBudgetExceeded
	}
	result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET reserved_micros = reserved_micros + $3, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND version >= 1`, tenantID, accountID, amountMicros)
	if err != nil {
		return Reservation{}, false, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, false, err
	}
	createdAt := ledger.clock().UTC()
	generatedID, err := newReservationID()
	if err != nil {
		return Reservation{}, false, err
	}
	reservation := Reservation{ID: generatedID, TenantID: tenantID, AccountID: accountID, RequestID: requestID, ReservedMicros: amountMicros, State: ReservationOpen, CreatedAt: createdAt, ExpiresAt: createdAt.Add(ledger.reservationTTL)}
	_, err = tx.ExecContext(ctx, `
INSERT INTO budget_reservations
  (tenant_id, id, idempotency_key, account_id, request_id, estimated_micros, state, expires_at, created_at, updated_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, 'RESERVED', $7, $8, $8)`,
		tenantID, generatedID, reservationID, accountID, requestID, amountMicros, createdAt.Add(ledger.reservationTTL), createdAt)
	if err != nil {
		return Reservation{}, false, mapBudgetSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return Reservation{}, false, err
	}
	return reservation, true, nil
}

func (ledger *PostgresBudgetLedger) Settle(ctx context.Context, tenantID, reservationID string, actualMicros int64) (Reservation, error) {
	return ledger.settle(ctx, tenantID, reservationID, actualMicros, false)
}

func (ledger *PostgresBudgetLedger) Reconcile(ctx context.Context, tenantID, reservationID string, actualMicros int64) (Reservation, error) {
	return ledger.settle(ctx, tenantID, reservationID, actualMicros, true)
}

func (ledger *PostgresBudgetLedger) settle(ctx context.Context, tenantID, reservationID string, actualMicros int64, allowReconcile bool) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if tenantID == "" || reservationID == "" || actualMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, tenantID)
	if err != nil {
		return Reservation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	reservation, found, err := loadBudgetReservation(ctx, tx, tenantID, reservationID, true)
	if err != nil {
		return Reservation{}, err
	}
	if !found {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.State == ReservationSettled {
		if reservation.SettledMicros != actualMicros {
			return Reservation{}, ErrReservationConflict
		}
		if err := tx.Commit(); err != nil {
			return Reservation{}, err
		}
		return reservation, nil
	}
	validState := reservation.State == ReservationOpen || allowReconcile && reservation.State == ReservationReconcile
	if !validState {
		return Reservation{}, ErrReservationConflict
	}
	account, found, err := loadBudgetAccount(ctx, tx, tenantID, reservation.AccountID, true)
	if err != nil {
		return Reservation{}, err
	}
	if !found || account.ReservedMicros < reservation.ReservedMicros || actualMicros > account.LimitMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET reserved_micros = reserved_micros - $3, spent_micros = spent_micros + $4, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND reserved_micros >= $3`, tenantID, reservation.AccountID, reservation.ReservedMicros, actualMicros)
	if err != nil {
		return Reservation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE budget_reservations
SET actual_micros = $3, state = 'SETTLED', updated_at = $4
WHERE tenant_id = $1::uuid AND id = $2 AND state = $5`, tenantID, reservation.ID, actualMicros, ledger.clock().UTC(), string(reservation.State))
	if err != nil {
		return Reservation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, err
	}
	reservation.SettledMicros = actualMicros
	reservation.State = ReservationSettled
	if err := tx.Commit(); err != nil {
		return Reservation{}, err
	}
	return reservation, nil
}

func (ledger *PostgresBudgetLedger) Release(ctx context.Context, tenantID, reservationID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if tenantID == "" || reservationID == "" {
		return ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, tenantID)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	reservation, found, err := loadBudgetReservation(ctx, tx, tenantID, reservationID, true)
	if err != nil {
		return err
	}
	if !found {
		return ErrReservationNotFound
	}
	if reservation.State == ReservationReleased {
		return tx.Commit()
	}
	if reservation.State != ReservationOpen {
		return ErrReservationConflict
	}
	result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET reserved_micros = reserved_micros - $3, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND reserved_micros >= $3`, tenantID, reservation.AccountID, reservation.ReservedMicros)
	if err != nil {
		return err
	}
	if err := requireOneRow(result); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE budget_reservations
SET state = 'RELEASED', updated_at = $3
	WHERE tenant_id = $1::uuid AND id = $2 AND state = 'RESERVED'`, tenantID, reservation.ID, ledger.clock().UTC())
	if err != nil {
		return err
	}
	if err := requireOneRow(result); err != nil {
		return err
	}
	return tx.Commit()
}

func (ledger *PostgresBudgetLedger) RequireReconciliation(ctx context.Context, tenantID, reservationID string) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if tenantID == "" || reservationID == "" {
		return Reservation{}, ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, tenantID)
	if err != nil {
		return Reservation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	reservation, found, err := loadBudgetReservation(ctx, tx, tenantID, reservationID, true)
	if err != nil {
		return Reservation{}, err
	}
	if !found {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.State == ReservationReconcile {
		if err := tx.Commit(); err != nil {
			return Reservation{}, err
		}
		return reservation, nil
	}
	if reservation.State != ReservationOpen {
		return Reservation{}, ErrReservationConflict
	}
	result, err := tx.ExecContext(ctx, `
UPDATE budget_reservations
SET state = 'RECONCILE', updated_at = $3
	WHERE tenant_id = $1::uuid AND id = $2 AND state = 'RESERVED'`, tenantID, reservation.ID, ledger.clock().UTC())
	if err != nil {
		return Reservation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, err
	}
	reservation.State = ReservationReconcile
	if err := tx.Commit(); err != nil {
		return Reservation{}, err
	}
	return reservation, nil
}

func (ledger *PostgresBudgetLedger) Account(ctx context.Context, tenantID, accountID string) (BudgetAccount, bool, error) {
	if err := contextError(ctx); err != nil {
		return BudgetAccount{}, false, err
	}
	tx, err := ledger.beginReadOnly(ctx, tenantID)
	if err != nil {
		return BudgetAccount{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	account, found, err := loadBudgetAccount(ctx, tx, tenantID, accountID, false)
	if err != nil || !found {
		return account, found, err
	}
	if err := tx.Commit(); err != nil {
		return BudgetAccount{}, false, err
	}
	return account, true, nil
}

func (ledger *PostgresBudgetLedger) ExpireReservations(ctx context.Context, tenantID string, limit int) ([]Reservation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if tenantID == "" || limit <= 0 {
		return nil, ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
WITH expired AS (
  SELECT id
  FROM budget_reservations
	  WHERE tenant_id = $1::uuid AND state = 'RESERVED' AND expires_at <= $2
  ORDER BY expires_at, id
  LIMIT $3
  FOR UPDATE SKIP LOCKED
)
UPDATE budget_reservations AS reservation
SET state = 'RECONCILE', updated_at = $2
FROM expired
WHERE reservation.tenant_id = $1::uuid AND reservation.id = expired.id
RETURNING reservation.id, reservation.tenant_id::text, reservation.account_id, reservation.request_id,
          reservation.estimated_micros, coalesce(reservation.actual_micros, 0), reservation.state,
          reservation.created_at, reservation.expires_at`, tenantID, ledger.clock().UTC(), limit)
	if err != nil {
		return nil, err
	}
	reservations := []Reservation{}
	for rows.Next() {
		var reservation Reservation
		if err := rows.Scan(&reservation.ID, &reservation.TenantID, &reservation.AccountID, &reservation.RequestID, &reservation.ReservedMicros, &reservation.SettledMicros, &reservation.State, &reservation.CreatedAt, &reservation.ExpiresAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		reservations = append(reservations, reservation)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return reservations, nil
}

func (ledger *PostgresBudgetLedger) begin(ctx context.Context, tenantID string) (*sql.Tx, error) {
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	if err := setBudgetTenant(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (ledger *PostgresBudgetLedger) beginReadOnly(ctx context.Context, tenantID string) (*sql.Tx, error) {
	tx, err := ledger.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	if err := setBudgetTenant(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func setBudgetTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if tenantID == "" {
		return ErrInvalidRequest
	}
	var superuser bool
	var bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		return err
	}
	if superuser || bypassRLS {
		return ErrInvalidRequest
	}
	_, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID)
	return err
}

func loadBudgetAccount(ctx context.Context, tx *sql.Tx, tenantID, accountID string, lock bool) (BudgetAccount, bool, error) {
	query := `
	SELECT id, tenant_id::text, scope_type, scope_id, currency, hard_limit_micros,
	       soft_limit_micros, reserved_micros, spent_micros, period_start, period_end, version
	FROM budget_accounts
WHERE tenant_id = $1::uuid AND id = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	var account BudgetAccount
	err := tx.QueryRowContext(ctx, query, tenantID, accountID).Scan(
		&account.ID, &account.TenantID, &account.ScopeType, &account.ScopeID, &account.Currency,
		&account.LimitMicros, &account.SoftLimitMicros, &account.ReservedMicros, &account.SpentMicros,
		&account.PeriodStart, &account.PeriodEnd, &account.Version,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return BudgetAccount{}, false, nil
	}
	return account, err == nil, err
}

func loadProjectBudgetAccount(ctx context.Context, tx *sql.Tx, tenantID, projectID string, lock bool) (BudgetAccount, bool, error) {
	query := `
SELECT id, tenant_id::text, scope_type, scope_id, currency, hard_limit_micros,
       soft_limit_micros, reserved_micros, spent_micros, period_start, period_end, version
FROM budget_accounts
WHERE tenant_id = $1::uuid AND scope_type = 'PROJECT' AND scope_id = $2
ORDER BY id`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, query, tenantID, projectID)
	if err != nil {
		return BudgetAccount{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return BudgetAccount{}, false, err
		}
		return BudgetAccount{}, false, nil
	}
	var account BudgetAccount
	if err := rows.Scan(
		&account.ID, &account.TenantID, &account.ScopeType, &account.ScopeID, &account.Currency,
		&account.LimitMicros, &account.SoftLimitMicros, &account.ReservedMicros, &account.SpentMicros,
		&account.PeriodStart, &account.PeriodEnd, &account.Version,
	); err != nil {
		return BudgetAccount{}, false, err
	}
	if rows.Next() {
		return BudgetAccount{}, false, ErrBudgetAccountConflict
	}
	if err := rows.Err(); err != nil {
		return BudgetAccount{}, false, err
	}
	return account, true, nil
}

func loadBudgetReservation(ctx context.Context, tx *sql.Tx, tenantID, reservationID string, lock bool) (Reservation, bool, error) {
	query := `
SELECT id, tenant_id::text, account_id, request_id, estimated_micros, coalesce(actual_micros, 0), state, created_at, expires_at
FROM budget_reservations
WHERE tenant_id = $1::uuid AND (id = $2 OR idempotency_key = $2)
ORDER BY CASE WHEN id = $2 THEN 0 ELSE 1 END
LIMIT 1`
	if lock {
		query += ` FOR UPDATE`
	}
	var reservation Reservation
	err := tx.QueryRowContext(ctx, query, tenantID, reservationID).Scan(
		&reservation.ID, &reservation.TenantID, &reservation.AccountID, &reservation.RequestID,
		&reservation.ReservedMicros, &reservation.SettledMicros, &reservation.State, &reservation.CreatedAt, &reservation.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Reservation{}, false, nil
	}
	return reservation, err == nil, err
}

func loadBudgetReservationByRequest(ctx context.Context, tx *sql.Tx, tenantID, requestID string, lock bool) (Reservation, bool, error) {
	query := `
	SELECT id, tenant_id::text, account_id, request_id, estimated_micros,
	       COALESCE(actual_micros, 0), state, expires_at, created_at
	FROM budget_reservations
	WHERE tenant_id = $1::uuid AND request_id = $2
	ORDER BY id
	LIMIT 1`
	if lock {
		query += ` FOR UPDATE`
	}
	var reservation Reservation
	err := tx.QueryRowContext(ctx, query, tenantID, requestID).Scan(
		&reservation.ID, &reservation.TenantID, &reservation.AccountID, &reservation.RequestID,
		&reservation.ReservedMicros, &reservation.SettledMicros, &reservation.State,
		&reservation.ExpiresAt, &reservation.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Reservation{}, false, nil
	}
	if err != nil {
		return Reservation{}, false, err
	}
	reservation.CreatedAt = reservation.CreatedAt.UTC()
	reservation.ExpiresAt = reservation.ExpiresAt.UTC()
	return reservation, true, nil
}

func requireOneRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrReservationConflict
	}
	return nil
}

type sqlStateError interface {
	SQLState() string
}

func mapBudgetSQLError(err error) error {
	var state sqlStateError
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return ErrReservationConflict
	}
	return err
}

var _ BudgetLedgerBackend = (*PostgresBudgetLedger)(nil)
var _ BudgetReservationClaimer = (*PostgresBudgetLedger)(nil)
