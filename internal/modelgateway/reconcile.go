package modelgateway

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const MaximumUsageReceiptBytes = 256 << 10

// UsageReconciliationRequest is accepted only from the trusted reconciliation
// path after provider billing data has been retrieved. RawUsage is retained by
// digest, while the adapter normalizes the provider-specific fields.
type UsageReconciliationRequest struct {
	TenantID      string
	RequestID     string
	ReservationID string
	Provider      string
	Model         string
	RawUsage      json.RawMessage
}

type ModelCallReconciliation struct {
	TenantID      string
	RequestID     string
	ReservationID string
	Provider      string
	Model         string
	Usage         Usage
	ActualMicros  int64
	ReceiptSHA256 string
	ReconciledAt  time.Time
}

type ModelCallReconciler interface {
	ReconcileModelCall(context.Context, ModelCallReconciliation) (Reservation, error)
}

func (g *Gateway) ReconcileUsage(ctx context.Context, request UsageReconciliationRequest) (Reservation, error) {
	if g == nil || ctx == nil || request.TenantID == "" || request.RequestID == "" || request.ReservationID == "" || request.Provider == "" || request.Model == "" || len(request.RawUsage) == 0 || len(request.RawUsage) > MaximumUsageReceiptBytes || !json.Valid(request.RawUsage) {
		return Reservation{}, ErrInvalidRequest
	}
	if g.callLookup == nil {
		return Reservation{}, ErrReconciliationRequired
	}
	call, found, err := g.callLookup.LookupModelCall(ctx, request.TenantID, request.RequestID)
	if err != nil {
		return Reservation{}, err
	}
	if !found || call.Provider != request.Provider || call.LogicalModel != request.Model || call.Status != ModelCallReconcile && call.Status != ModelCallReconciled {
		return Reservation{}, ErrRequestConflict
	}
	key := request.Provider + "\x00" + request.Model
	adapter, pricing, allowed := g.provider(key, request.Provider, request.Model)
	if adapter == nil || !allowed {
		return Reservation{}, ErrProviderNotAllowed
	}
	usage, err := adapter.NormalizeUsage(append(json.RawMessage(nil), request.RawUsage...))
	if err != nil || usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 || usage.ProviderRequestID == "" || usage.ModelVersion == "" || strings.ContainsAny(usage.ProviderRequestID+usage.ModelVersion, "\r\n\x00") {
		return Reservation{}, ErrInvalidRequest
	}
	if call.Status == ModelCallReconciled && call.ProviderRequestID != usage.ProviderRequestID || call.ActualModelVersion != "" && call.ActualModelVersion != "NON_REPRODUCIBLE_PROVIDER" && call.ActualModelVersion != usage.ModelVersion {
		return Reservation{}, ErrRequestConflict
	}
	receiptMicros, err := usageCost(usage, pricing)
	if err != nil {
		return Reservation{}, err
	}
	receiptSHA256, err := canonicaljson.Digest(request.RawUsage)
	if err != nil {
		return Reservation{}, ErrInvalidRequest
	}
	reconciler, ok := g.ledger.(ModelCallReconciler)
	if !ok {
		return Reservation{}, ErrReconciliationRequired
	}
	actualMicros := call.CostMicros
	if call.Status == ModelCallReconciled {
		usage.InputTokens = call.InputTokens
		usage.OutputTokens = call.OutputTokens
	} else {
		actualMicros, err = addCost(actualMicros, receiptMicros)
		if err != nil {
			return Reservation{}, err
		}
		usage.InputTokens, err = addCost(call.InputTokens, usage.InputTokens)
		if err != nil {
			return Reservation{}, err
		}
		usage.OutputTokens, err = addCost(call.OutputTokens, usage.OutputTokens)
		if err != nil {
			return Reservation{}, err
		}
	}
	reconcileContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return reconciler.ReconcileModelCall(reconcileContext, ModelCallReconciliation{
		TenantID: request.TenantID, RequestID: request.RequestID, ReservationID: request.ReservationID,
		Provider: request.Provider, Model: request.Model, Usage: usage, ActualMicros: actualMicros,
		ReceiptSHA256: receiptSHA256, ReconciledAt: g.clock().UTC(),
	})
}

func (reconciliation ModelCallReconciliation) validate() error {
	if reconciliation.TenantID == "" || reconciliation.RequestID == "" || reconciliation.ReservationID == "" || reconciliation.Provider == "" || reconciliation.Model == "" || reconciliation.Usage.ProviderRequestID == "" || reconciliation.Usage.ModelVersion == "" || reconciliation.Usage.InputTokens < 0 || reconciliation.Usage.OutputTokens < 0 || reconciliation.Usage.CostMicros < 0 || reconciliation.ActualMicros < 0 || !validModelDigest(reconciliation.ReceiptSHA256) || reconciliation.ReconciledAt.IsZero() {
		return ErrInvalidRequest
	}
	for _, value := range []string{reconciliation.TenantID, reconciliation.RequestID, reconciliation.ReservationID, reconciliation.Provider, reconciliation.Model, reconciliation.Usage.ProviderRequestID, reconciliation.Usage.ModelVersion} {
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return ErrInvalidRequest
		}
	}
	return nil
}

func (ledger *BudgetLedger) ReconcileModelCall(ctx context.Context, reconciliation ModelCallReconciliation) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if ledger == nil || reconciliation.validate() != nil {
		return Reservation{}, ErrInvalidRequest
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	callKey := budgetKey(reconciliation.TenantID, reconciliation.RequestID)
	call, found := ledger.modelCalls[callKey]
	if !found || call.Provider != reconciliation.Provider || call.LogicalModel != reconciliation.Model {
		return Reservation{}, ErrRequestConflict
	}
	reservationKey, reservation, found := ledger.lookupReservationLocked(reconciliation.TenantID, reconciliation.ReservationID)
	if !found {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.RequestID != reconciliation.RequestID {
		return Reservation{}, ErrReservationConflict
	}
	if call.Status == ModelCallReconciled {
		if reservation.State != ReservationSettled || reservation.SettledMicros != reconciliation.ActualMicros || !sameReconciliation(call, reconciliation) {
			return Reservation{}, ErrReservationConflict
		}
		return reservation, nil
	}
	if call.Status != ModelCallReconcile || reservation.State != ReservationReconcile {
		return Reservation{}, ErrReservationConflict
	}
	accountKey := budgetKey(reconciliation.TenantID, reservation.AccountID)
	account, found := ledger.accounts[accountKey]
	if !found || account.ReservedMicros < reservation.ReservedMicros || reconciliation.ActualMicros > account.LimitMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.ReservedMicros -= reservation.ReservedMicros
	account.SpentMicros += reconciliation.ActualMicros
	account.Version++
	ledger.accounts[accountKey] = account
	reservation.SettledMicros = reconciliation.ActualMicros
	reservation.State = ReservationSettled
	ledger.reservations[reservationKey] = reservation
	applyReconciliation(&call, reconciliation)
	ledger.modelCalls[callKey] = call
	return reservation, nil
}

func sameReconciliation(call ModelCall, reconciliation ModelCallReconciliation) bool {
	return call.Status == ModelCallReconciled && call.InputTokens == reconciliation.Usage.InputTokens && call.OutputTokens == reconciliation.Usage.OutputTokens && call.CostMicros == reconciliation.ActualMicros && call.ProviderRequestID == reconciliation.Usage.ProviderRequestID && call.ActualModelVersion == reconciliation.Usage.ModelVersion && call.ReconciliationReceiptSHA256 == reconciliation.ReceiptSHA256
}

func applyReconciliation(call *ModelCall, reconciliation ModelCallReconciliation) {
	call.InputTokens = reconciliation.Usage.InputTokens
	call.OutputTokens = reconciliation.Usage.OutputTokens
	call.CostMicros = reconciliation.ActualMicros
	call.ProviderRequestID = reconciliation.Usage.ProviderRequestID
	call.ActualModelVersion = reconciliation.Usage.ModelVersion
	call.Status = ModelCallReconciled
	call.ReconciliationReceiptSHA256 = reconciliation.ReceiptSHA256
	reconciledAt := reconciliation.ReconciledAt.UTC()
	call.ReconciledAt = &reconciledAt
}

var _ ModelCallReconciler = (*BudgetLedger)(nil)
