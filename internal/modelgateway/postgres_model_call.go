package modelgateway

import (
	"context"
	"database/sql"
	"errors"
)

func (ledger *PostgresBudgetLedger) FinalizeModelCall(ctx context.Context, finalization ModelCallFinalization) (Reservation, error) {
	return ledger.finalizeModelCall(ctx, finalization, nil)
}

func (ledger *PostgresBudgetLedger) FinalizeModelCallWithReplay(ctx context.Context, finalization ModelCallFinalization, replay ModelReplay) (Reservation, error) {
	if !ledger.ReplayEnabled() || validateModelReplay(finalization, replay) != nil {
		return Reservation{}, ErrInvalidRequest
	}
	return ledger.finalizeModelCall(ctx, finalization, &replay)
}

func (ledger *PostgresBudgetLedger) finalizeModelCall(ctx context.Context, finalization ModelCallFinalization, replay *ModelReplay) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if ledger == nil || finalization.validate() != nil {
		return Reservation{}, ErrInvalidRequest
	}
	if finalization.Call.ID == "" {
		id, err := newModelCallID()
		if err != nil {
			return Reservation{}, err
		}
		finalization.Call.ID = id
	}
	tx, err := ledger.begin(ctx, finalization.Call.TenantID)
	if err != nil {
		return Reservation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	reservation, found, err := loadBudgetReservation(ctx, tx, finalization.Call.TenantID, finalization.ReservationID, true)
	if err != nil {
		return Reservation{}, err
	}
	if !found {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.RequestID != finalization.Call.RequestID {
		return Reservation{}, ErrReservationConflict
	}
	existing, found, err := loadModelCall(ctx, tx, finalization.Call.TenantID, finalization.Call.RequestID)
	if err != nil {
		return Reservation{}, err
	}
	if found {
		if !sameModelCall(existing, finalization.Call) {
			return Reservation{}, ErrReservationConflict
		}
		if replay != nil {
			if err := ledger.insertModelReplayTx(ctx, tx, finalization.Call.TenantID, finalization.Call.RequestID, *replay); err != nil {
				return Reservation{}, err
			}
		}
		if err := tx.Commit(); err != nil {
			return Reservation{}, err
		}
		return reservation, nil
	}
	reservation, err = ledger.finalizeReservationTx(ctx, tx, finalization, reservation)
	if err != nil {
		return Reservation{}, err
	}
	inserted, err := insertModelCall(ctx, tx, finalization.Call)
	if err != nil {
		return Reservation{}, mapBudgetSQLError(err)
	}
	if !inserted {
		existing, found, err = loadModelCall(ctx, tx, finalization.Call.TenantID, finalization.Call.RequestID)
		if err != nil || !found || !sameModelCall(existing, finalization.Call) {
			return Reservation{}, ErrReservationConflict
		}
	}
	if replay != nil {
		if err := ledger.insertModelReplayTx(ctx, tx, finalization.Call.TenantID, finalization.Call.RequestID, *replay); err != nil {
			return Reservation{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Reservation{}, err
	}
	return reservation, nil
}

func (ledger *PostgresBudgetLedger) finalizeReservationTx(ctx context.Context, tx *sql.Tx, finalization ModelCallFinalization, reservation Reservation) (Reservation, error) {
	tenantID := finalization.Call.TenantID
	switch finalization.Disposition {
	case ReservationDispositionSettle:
		if reservation.State == ReservationSettled {
			if reservation.SettledMicros != finalization.ActualMicros {
				return Reservation{}, ErrReservationConflict
			}
			return reservation, nil
		}
		if reservation.State != ReservationOpen {
			return Reservation{}, ErrReservationConflict
		}
		account, found, err := loadBudgetAccount(ctx, tx, tenantID, reservation.AccountID, true)
		if err != nil {
			return Reservation{}, err
		}
		if !found || account.ReservedMicros < reservation.ReservedMicros || finalization.ActualMicros > account.LimitMicros-account.SpentMicros {
			return Reservation{}, ErrBudgetExceeded
		}
		result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET reserved_micros = reserved_micros - $3, spent_micros = spent_micros + $4, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND reserved_micros >= $3`, tenantID, reservation.AccountID, reservation.ReservedMicros, finalization.ActualMicros)
		if err != nil {
			return Reservation{}, err
		}
		if err := requireOneRow(result); err != nil {
			return Reservation{}, err
		}
		result, err = tx.ExecContext(ctx, `
UPDATE budget_reservations
SET actual_micros = $3, state = 'SETTLED', updated_at = $4
WHERE tenant_id = $1::uuid AND id = $2 AND state = 'RESERVED'`, tenantID, reservation.ID, finalization.ActualMicros, ledger.clock().UTC())
		if err != nil {
			return Reservation{}, err
		}
		if err := requireOneRow(result); err != nil {
			return Reservation{}, err
		}
		reservation.SettledMicros = finalization.ActualMicros
		reservation.State = ReservationSettled
		return reservation, nil
	case ReservationDispositionRelease:
		if reservation.State == ReservationReleased {
			return reservation, nil
		}
		if reservation.State != ReservationOpen {
			return Reservation{}, ErrReservationConflict
		}
		result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET reserved_micros = reserved_micros - $3, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND reserved_micros >= $3`, tenantID, reservation.AccountID, reservation.ReservedMicros)
		if err != nil {
			return Reservation{}, err
		}
		if err := requireOneRow(result); err != nil {
			return Reservation{}, err
		}
		result, err = tx.ExecContext(ctx, `
UPDATE budget_reservations
SET state = 'RELEASED', updated_at = $3
WHERE tenant_id = $1::uuid AND id = $2 AND state = 'RESERVED'`, tenantID, reservation.ID, ledger.clock().UTC())
		if err != nil {
			return Reservation{}, err
		}
		if err := requireOneRow(result); err != nil {
			return Reservation{}, err
		}
		reservation.State = ReservationReleased
		return reservation, nil
	case ReservationDispositionReconcile:
		if reservation.State == ReservationReconcile {
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
		return reservation, nil
	default:
		return Reservation{}, ErrInvalidRequest
	}
}

func insertModelCall(ctx context.Context, tx *sql.Tx, call ModelCall) (bool, error) {
	result, err := tx.ExecContext(ctx, `
INSERT INTO model_calls
  (id, tenant_id, request_id, project_id, task_id, agent_instance_id, provider,
   logical_model, actual_model_version, prompt_bundle_version, input_sha256,
   output_sha256, input_tokens, output_tokens, cache_read_tokens,
   cache_write_tokens, cost_micros, latency_ms, status, provider_request_id,
   created_at)
VALUES
  ($1::uuid, $2::uuid, $3, $4::uuid, NULLIF($5, '')::uuid, $6, $7, $8, $9,
   $10, $11, NULLIF($12, ''), $13, $14, $15, $16, $17, $18, $19,
   NULLIF($20, ''), $21)
ON CONFLICT (tenant_id, request_id) DO NOTHING`, call.ID, call.TenantID, call.RequestID,
		call.ProjectID, call.TaskID, call.AgentInstanceID, call.Provider, call.LogicalModel,
		call.ActualModelVersion, call.PromptBundleVersion, call.InputSHA256, call.OutputSHA256,
		call.InputTokens, call.OutputTokens, call.CacheReadTokens, call.CacheWriteTokens,
		call.CostMicros, call.LatencyMilliseconds, string(call.Status), call.ProviderRequestID,
		call.CreatedAt.UTC())
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func loadModelCall(ctx context.Context, tx *sql.Tx, tenantID, requestID string) (ModelCall, bool, error) {
	var call ModelCall
	var taskID, outputSHA, providerRequest sql.NullString
	var cacheRead, cacheWrite sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT id::text, tenant_id::text, request_id, project_id::text, task_id::text,
       agent_instance_id, provider, logical_model, actual_model_version,
       prompt_bundle_version, input_sha256, output_sha256, input_tokens,
       output_tokens, cache_read_tokens, cache_write_tokens, cost_micros,
       latency_ms, status, provider_request_id, created_at
FROM model_calls
WHERE tenant_id = $1::uuid AND request_id = $2`, tenantID, requestID).Scan(
		&call.ID, &call.TenantID, &call.RequestID, &call.ProjectID, &taskID,
		&call.AgentInstanceID, &call.Provider, &call.LogicalModel, &call.ActualModelVersion,
		&call.PromptBundleVersion, &call.InputSHA256, &outputSHA, &call.InputTokens,
		&call.OutputTokens, &cacheRead, &cacheWrite, &call.CostMicros,
		&call.LatencyMilliseconds, &call.Status, &providerRequest, &call.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ModelCall{}, false, nil
	}
	if err != nil {
		return ModelCall{}, false, err
	}
	call.TaskID = taskID.String
	call.OutputSHA256 = outputSHA.String
	call.ProviderRequestID = providerRequest.String
	if cacheRead.Valid {
		value := cacheRead.Int64
		call.CacheReadTokens = &value
	}
	if cacheWrite.Valid {
		value := cacheWrite.Int64
		call.CacheWriteTokens = &value
	}
	call.CreatedAt = call.CreatedAt.UTC()
	return call, true, nil
}

var _ ModelCallFinalizer = (*PostgresBudgetLedger)(nil)
var _ ModelCallReplayFinalizer = (*PostgresBudgetLedger)(nil)
