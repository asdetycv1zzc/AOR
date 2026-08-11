package modelgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ModelCallStatus string

const (
	ModelCallSucceeded          ModelCallStatus = "SUCCEEDED"
	ModelCallFailedProvider     ModelCallStatus = "FAILED_PROVIDER"
	ModelCallFailedOutputSchema ModelCallStatus = "FAILED_OUTPUT_SCHEMA"
	ModelCallFailedOutputSize   ModelCallStatus = "FAILED_OUTPUT_SIZE"
	ModelCallFailedCredential   ModelCallStatus = "FAILED_CREDENTIAL"
	ModelCallReconcile          ModelCallStatus = "RECONCILE"
	ModelCallReconciled         ModelCallStatus = "RECONCILED"
)

type ReservationDisposition string

const (
	ReservationDispositionSettle    ReservationDisposition = "SETTLE"
	ReservationDispositionRelease   ReservationDisposition = "RELEASE"
	ReservationDispositionReconcile ReservationDisposition = "RECONCILE"
)

type ModelCall struct {
	ID                          string          `json:"id"`
	TenantID                    string          `json:"tenantId"`
	RequestID                   string          `json:"requestId"`
	ProjectID                   string          `json:"projectId"`
	TaskID                      string          `json:"taskId,omitempty"`
	AgentInstanceID             string          `json:"agentInstanceId"`
	Provider                    string          `json:"provider"`
	LogicalModel                string          `json:"logicalModel"`
	ActualModelVersion          string          `json:"actualModelVersion"`
	PromptBundleVersion         string          `json:"promptBundleVersion"`
	InputSHA256                 string          `json:"inputSha256"`
	OutputSHA256                string          `json:"outputSha256,omitempty"`
	InputTokens                 int64           `json:"inputTokens"`
	OutputTokens                int64           `json:"outputTokens"`
	CacheReadTokens             *int64          `json:"cacheReadTokens,omitempty"`
	CacheWriteTokens            *int64          `json:"cacheWriteTokens,omitempty"`
	CostMicros                  int64           `json:"costMicros"`
	LatencyMilliseconds         int64           `json:"latencyMs"`
	Status                      ModelCallStatus `json:"status"`
	ProviderRequestID           string          `json:"providerRequestId,omitempty"`
	ReconciliationReceiptSHA256 string          `json:"reconciliationReceiptSha256,omitempty"`
	ReconciledAt                *time.Time      `json:"reconciledAt,omitempty"`
	CreatedAt                   time.Time       `json:"createdAt"`
}

type ModelCallFinalization struct {
	ReservationID string
	Disposition   ReservationDisposition
	ActualMicros  int64
	Call          ModelCall
}

type ModelCallFinalizer interface {
	FinalizeModelCall(context.Context, ModelCallFinalization) (Reservation, error)
}

type ModelCallReplayFinalizer interface {
	FinalizeModelCallWithReplay(context.Context, ModelCallFinalization, ModelReplay) (Reservation, error)
}

func (finalization ModelCallFinalization) validate() error {
	if finalization.ReservationID == "" || finalization.ActualMicros < 0 || !validDisposition(finalization.Disposition) {
		return ErrInvalidRequest
	}
	call := finalization.Call
	if call.TenantID == "" || call.RequestID == "" || call.ProjectID == "" || call.AgentInstanceID == "" || call.Provider == "" || call.LogicalModel == "" || call.ActualModelVersion == "" || call.PromptBundleVersion == "" || !validModelDigest(call.InputSHA256) || call.OutputSHA256 != "" && !validModelDigest(call.OutputSHA256) || call.InputTokens < 0 || call.OutputTokens < 0 || call.CostMicros < 0 || call.LatencyMilliseconds < 0 || !validModelCallStatus(call.Status) || call.CreatedAt.IsZero() || call.ReconciliationReceiptSHA256 != "" || call.ReconciledAt != nil {
		return ErrInvalidRequest
	}
	for _, value := range []string{call.TenantID, call.RequestID, call.ProjectID, call.TaskID, call.AgentInstanceID, call.Provider, call.LogicalModel, call.ActualModelVersion, call.PromptBundleVersion, call.ProviderRequestID} {
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return ErrInvalidRequest
		}
	}
	if call.CacheReadTokens != nil && *call.CacheReadTokens < 0 || call.CacheWriteTokens != nil && *call.CacheWriteTokens < 0 {
		return ErrInvalidRequest
	}
	switch finalization.Disposition {
	case ReservationDispositionSettle:
		if call.Status == ModelCallReconcile || call.Status == ModelCallReconciled || call.CostMicros != finalization.ActualMicros {
			return ErrInvalidRequest
		}
	case ReservationDispositionRelease:
		if finalization.ActualMicros != 0 || call.CostMicros != 0 || call.Status != ModelCallFailedProvider {
			return ErrInvalidRequest
		}
	case ReservationDispositionReconcile:
		if call.Status != ModelCallReconcile {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validDisposition(value ReservationDisposition) bool {
	return value == ReservationDispositionSettle || value == ReservationDispositionRelease || value == ReservationDispositionReconcile
}

func validModelCallStatus(value ModelCallStatus) bool {
	switch value {
	case ModelCallSucceeded, ModelCallFailedProvider, ModelCallFailedOutputSchema, ModelCallFailedOutputSize, ModelCallFailedCredential, ModelCallReconcile, ModelCallReconciled:
		return true
	default:
		return false
	}
}

func validModelDigest(value string) bool {
	return len(value) == len("sha256:")+sha256.Size*2 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[len("sha256:"):], "0123456789abcdef") == ""
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func newModelCallID() (string, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

func sameModelCall(left, right ModelCall) bool {
	return left.TenantID == right.TenantID && left.RequestID == right.RequestID && left.ProjectID == right.ProjectID && left.TaskID == right.TaskID && left.AgentInstanceID == right.AgentInstanceID && left.Provider == right.Provider && left.LogicalModel == right.LogicalModel && left.ActualModelVersion == right.ActualModelVersion && left.PromptBundleVersion == right.PromptBundleVersion && left.InputSHA256 == right.InputSHA256 && left.OutputSHA256 == right.OutputSHA256 && left.InputTokens == right.InputTokens && left.OutputTokens == right.OutputTokens && equalOptionalInt64(left.CacheReadTokens, right.CacheReadTokens) && equalOptionalInt64(left.CacheWriteTokens, right.CacheWriteTokens) && left.CostMicros == right.CostMicros && left.LatencyMilliseconds == right.LatencyMilliseconds && left.Status == right.Status && left.ProviderRequestID == right.ProviderRequestID && left.ReconciliationReceiptSHA256 == right.ReconciliationReceiptSHA256 && equalOptionalTime(left.ReconciledAt, right.ReconciledAt) && left.CreatedAt.Equal(right.CreatedAt)
}

func equalOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (ledger *BudgetLedger) FinalizeModelCall(ctx context.Context, finalization ModelCallFinalization) (Reservation, error) {
	return ledger.finalizeModelCall(ctx, finalization, nil)
}

func (ledger *BudgetLedger) FinalizeModelCallWithReplay(ctx context.Context, finalization ModelCallFinalization, replay ModelReplay) (Reservation, error) {
	if validateModelReplay(finalization, replay) != nil {
		return Reservation{}, ErrInvalidRequest
	}
	return ledger.finalizeModelCall(ctx, finalization, &replay)
}

func (ledger *BudgetLedger) finalizeModelCall(ctx context.Context, finalization ModelCallFinalization, replay *ModelReplay) (Reservation, error) {
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
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	callKey := budgetKey(finalization.Call.TenantID, finalization.Call.RequestID)
	if existing, found := ledger.modelCalls[callKey]; found {
		if !sameModelCall(existing, finalization.Call) {
			return Reservation{}, ErrReservationConflict
		}
		_, reservation, found := ledger.lookupReservationLocked(finalization.Call.TenantID, finalization.ReservationID)
		if !found {
			return Reservation{}, ErrReservationNotFound
		}
		if replay != nil {
			if err := ledger.storeModelReplayLocked(finalization.Call.TenantID, finalization.Call.RequestID, *replay); err != nil {
				return Reservation{}, err
			}
		}
		return reservation, nil
	}
	reservationKey, reservation, found := ledger.lookupReservationLocked(finalization.Call.TenantID, finalization.ReservationID)
	if !found {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.RequestID != finalization.Call.RequestID {
		return Reservation{}, ErrReservationConflict
	}
	accountKey := budgetKey(finalization.Call.TenantID, reservation.AccountID)
	account, found := ledger.accounts[accountKey]
	if !found {
		return Reservation{}, ErrBudgetExceeded
	}
	switch finalization.Disposition {
	case ReservationDispositionSettle:
		if reservation.State == ReservationSettled {
			if reservation.SettledMicros != finalization.ActualMicros {
				return Reservation{}, ErrReservationConflict
			}
			break
		}
		if reservation.State != ReservationOpen || account.ReservedMicros < reservation.ReservedMicros || finalization.ActualMicros > account.LimitMicros-account.SpentMicros {
			return Reservation{}, ErrReservationConflict
		}
		account.ReservedMicros -= reservation.ReservedMicros
		account.SpentMicros += finalization.ActualMicros
		account.Version++
		ledger.accounts[accountKey] = account
		reservation.SettledMicros = finalization.ActualMicros
		reservation.State = ReservationSettled
		ledger.reservations[reservationKey] = reservation
	case ReservationDispositionRelease:
		if reservation.State == ReservationReleased {
			break
		}
		if reservation.State != ReservationOpen || account.ReservedMicros < reservation.ReservedMicros {
			return Reservation{}, ErrReservationConflict
		}
		account.ReservedMicros -= reservation.ReservedMicros
		account.Version++
		ledger.accounts[accountKey] = account
		reservation.State = ReservationReleased
		ledger.reservations[reservationKey] = reservation
	case ReservationDispositionReconcile:
		if reservation.State != ReservationReconcile {
			if reservation.State != ReservationOpen {
				return Reservation{}, ErrReservationConflict
			}
			reservation.State = ReservationReconcile
			ledger.reservations[reservationKey] = reservation
		}
	}
	ledger.modelCalls[callKey] = finalization.Call
	if replay != nil {
		if err := ledger.storeModelReplayLocked(finalization.Call.TenantID, finalization.Call.RequestID, *replay); err != nil {
			return Reservation{}, err
		}
	}
	return reservation, nil
}

func validateModelReplay(finalization ModelCallFinalization, replay ModelReplay) error {
	call := finalization.Call
	if finalization.Disposition != ReservationDispositionSettle || call.Status != ModelCallSucceeded || replay.InputSHA256 != call.InputSHA256 || replay.Response.RequestID != call.RequestID || validateNormalizedResponseOutput(replay.Response) != nil || call.OutputSHA256 != responseOutputDigest(replay.Response) {
		return ErrInvalidRequest
	}
	return nil
}

func (ledger *BudgetLedger) storeModelReplayLocked(tenantID, requestID string, replay ModelReplay) error {
	key := budgetKey(tenantID, requestID)
	if existing, found := ledger.modelReplays[key]; found {
		if existing.InputSHA256 != replay.InputSHA256 || !sameNormalizedResponse(existing.Response, replay.Response) {
			return ErrRequestConflict
		}
		return nil
	}
	replay.Response = cloneNormalizedResponse(replay.Response)
	ledger.modelReplays[key] = replay
	return nil
}

func (ledger *BudgetLedger) ModelCall(tenantID, requestID string) (ModelCall, bool) {
	if ledger == nil {
		return ModelCall{}, false
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	call, found := ledger.modelCalls[budgetKey(tenantID, requestID)]
	return call, found
}

func (ledger *BudgetLedger) LookupModelCall(ctx context.Context, tenantID, requestID string) (ModelCall, bool, error) {
	if err := contextError(ctx); err != nil {
		return ModelCall{}, false, err
	}
	call, found := ledger.ModelCall(tenantID, requestID)
	return call, found, nil
}

func (*BudgetLedger) ReplayEnabled() bool { return true }

func (ledger *BudgetLedger) LoadModelReplay(ctx context.Context, tenantID, requestID string) (ModelReplay, bool, error) {
	if err := contextError(ctx); err != nil {
		return ModelReplay{}, false, err
	}
	if ledger == nil || tenantID == "" || requestID == "" {
		return ModelReplay{}, false, ErrInvalidRequest
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	replay, found := ledger.modelReplays[budgetKey(tenantID, requestID)]
	if !found {
		return ModelReplay{}, false, nil
	}
	replay.Response = cloneNormalizedResponse(replay.Response)
	return replay, true, nil
}

func (ledger *BudgetLedger) StoreModelReplay(ctx context.Context, tenantID, requestID string, replay ModelReplay) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if ledger == nil || tenantID == "" || requestID == "" || !validModelDigest(replay.InputSHA256) || replay.Response.RequestID != requestID || validateNormalizedResponseOutput(replay.Response) != nil {
		return ErrInvalidRequest
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := budgetKey(tenantID, requestID)
	if existing, found := ledger.modelReplays[key]; found {
		if existing.InputSHA256 != replay.InputSHA256 || !sameNormalizedResponse(existing.Response, replay.Response) {
			return ErrRequestConflict
		}
		return nil
	}
	call, found := ledger.modelCalls[key]
	if !found || call.Status != ModelCallSucceeded || call.InputSHA256 != replay.InputSHA256 || call.OutputSHA256 != responseOutputDigest(replay.Response) {
		return ErrRequestConflict
	}
	return ledger.storeModelReplayLocked(tenantID, requestID, replay)
}

func cloneNormalizedResponse(response NormalizedResponse) NormalizedResponse {
	response.Content = append(json.RawMessage(nil), response.Content...)
	response.ToolCalls = append([]ToolCall(nil), response.ToolCalls...)
	response.AppliedInterventions = append([]string(nil), response.AppliedInterventions...)
	response.Usage.CacheReadTokens = cloneOptionalInt64(response.Usage.CacheReadTokens)
	response.Usage.CacheWriteTokens = cloneOptionalInt64(response.Usage.CacheWriteTokens)
	for index := range response.ToolCalls {
		response.ToolCalls[index].Arguments = append(json.RawMessage(nil), response.ToolCalls[index].Arguments...)
	}
	return response
}

func sameNormalizedResponse(left, right NormalizedResponse) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

var _ ModelCallFinalizer = (*BudgetLedger)(nil)
var _ ModelCallReplayFinalizer = (*BudgetLedger)(nil)
var _ ModelReplayStore = (*BudgetLedger)(nil)
var _ ModelCallLookup = (*BudgetLedger)(nil)
