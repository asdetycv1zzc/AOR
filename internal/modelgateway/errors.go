package modelgateway

import "errors"

var (
	ErrBudgetExceeded            = errors.New("model budget exceeded")
	ErrReservationConflict       = errors.New("model budget reservation conflict")
	ErrReservationNotFound       = errors.New("model budget reservation not found")
	ErrReconciliationRequired    = errors.New("model budget reservation requires reconciliation")
	ErrBudgetAccountNotFound     = errors.New("budget account not found")
	ErrBudgetAccountConflict     = errors.New("budget account scope is ambiguous")
	ErrBudgetProjectConflict     = errors.New("budget project state changed before commit")
	ErrBudgetVersionConflict     = errors.New("budget account version conflict")
	ErrBudgetCurrencyConflict    = errors.New("budget account currency conflict")
	ErrBudgetLimitConflict       = errors.New("budget account limit conflicts with committed usage")
	ErrBudgetPeriodClosed        = errors.New("budget account period is not active")
	ErrBudgetIdempotencyConflict = errors.New("budget adjustment idempotency conflict")
	ErrRequestConflict           = errors.New("model request id conflicts with a different request")
	ErrReplayUnavailable         = errors.New("completed model request has no replayable response")
	ErrInvalidRequest            = errors.New("invalid normalized model request")
	ErrProviderNotAllowed        = errors.New("model provider or model is not allowed")
	ErrProviderUnavailable       = errors.New("model provider is temporarily unavailable")
	ErrOutputSchema              = errors.New("model output does not satisfy response schema")
	ErrOutputTooLarge            = errors.New("model output exceeds the response size limit")
	ErrCredentialDetected        = errors.New("credential-like content rejected")
)
