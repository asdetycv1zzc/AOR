package modelgateway

import (
	"context"
)

func (ledger *PostgresBudgetLedger) ReconcileModelCall(ctx context.Context, reconciliation ModelCallReconciliation) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if ledger == nil || reconciliation.validate() != nil {
		return Reservation{}, ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, reconciliation.TenantID)
	if err != nil {
		return Reservation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	reservation, found, err := loadBudgetReservation(ctx, tx, reconciliation.TenantID, reconciliation.ReservationID, true)
	if err != nil {
		return Reservation{}, err
	}
	if !found {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.RequestID != reconciliation.RequestID {
		return Reservation{}, ErrReservationConflict
	}
	call, found, err := loadModelCall(ctx, tx, reconciliation.TenantID, reconciliation.RequestID)
	if err != nil {
		return Reservation{}, err
	}
	if !found || call.Provider != reconciliation.Provider || call.LogicalModel != reconciliation.Model {
		return Reservation{}, ErrRequestConflict
	}
	if call.Status == ModelCallReconciled {
		if reservation.State != ReservationSettled || reservation.SettledMicros != reconciliation.ActualMicros || !sameReconciliation(call, reconciliation) {
			return Reservation{}, ErrReservationConflict
		}
		if err := tx.Commit(); err != nil {
			return Reservation{}, err
		}
		return reservation, nil
	}
	if call.Status != ModelCallReconcile || reservation.State != ReservationReconcile {
		return Reservation{}, ErrReservationConflict
	}
	account, found, err := loadBudgetAccount(ctx, tx, reconciliation.TenantID, reservation.AccountID, true)
	if err != nil {
		return Reservation{}, err
	}
	if !found || account.ReservedMicros < reservation.ReservedMicros || reconciliation.ActualMicros > account.LimitMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET reserved_micros = reserved_micros - $3, spent_micros = spent_micros + $4, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND reserved_micros >= $3`, reconciliation.TenantID, reservation.AccountID, reservation.ReservedMicros, reconciliation.ActualMicros)
	if err != nil {
		return Reservation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE budget_reservations
SET actual_micros = $3, state = 'SETTLED', updated_at = $4
	WHERE tenant_id = $1::uuid AND id = $2 AND state = 'RECONCILE'`, reconciliation.TenantID, reservation.ID, reconciliation.ActualMicros, ledger.clock().UTC())
	if err != nil {
		return Reservation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE model_calls
SET actual_model_version = $4, input_tokens = $5, output_tokens = $6,
    cost_micros = $7, status = 'RECONCILED', provider_request_id = $8,
    reconciliation_receipt_sha256 = $9, reconciled_at = $10
WHERE tenant_id = $1::uuid AND request_id = $2 AND provider = $3 AND status = 'RECONCILE'`,
		reconciliation.TenantID, reconciliation.RequestID, reconciliation.Provider, reconciliation.Usage.ModelVersion,
		reconciliation.Usage.InputTokens, reconciliation.Usage.OutputTokens, reconciliation.ActualMicros,
		reconciliation.Usage.ProviderRequestID, reconciliation.ReceiptSHA256, reconciliation.ReconciledAt.UTC())
	if err != nil {
		return Reservation{}, err
	}
	if err := requireOneRow(result); err != nil {
		return Reservation{}, err
	}
	reservation.SettledMicros = reconciliation.ActualMicros
	reservation.State = ReservationSettled
	if err := tx.Commit(); err != nil {
		return Reservation{}, err
	}
	return reservation, nil
}

var _ ModelCallReconciler = (*PostgresBudgetLedger)(nil)
