package modelgateway

import "errors"

var (
	ErrBudgetExceeded         = errors.New("model budget exceeded")
	ErrReservationConflict    = errors.New("model budget reservation conflict")
	ErrReservationNotFound    = errors.New("model budget reservation not found")
	ErrReconciliationRequired = errors.New("model budget reservation requires reconciliation")
	ErrInvalidRequest         = errors.New("invalid normalized model request")
	ErrProviderNotAllowed     = errors.New("model provider or model is not allowed")
	ErrProviderUnavailable    = errors.New("model provider is temporarily unavailable")
	ErrOutputSchema           = errors.New("model output does not satisfy response schema")
	ErrOutputTooLarge         = errors.New("model output exceeds the response size limit")
	ErrCredentialDetected     = errors.New("credential-like content rejected")
)
