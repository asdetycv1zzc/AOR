package modelgateway

import "errors"

var (
	ErrBudgetExceeded      = errors.New("model budget exceeded")
	ErrReservationConflict = errors.New("model budget reservation conflict")
	ErrReservationNotFound = errors.New("model budget reservation not found")
	ErrInvalidRequest      = errors.New("invalid normalized model request")
	ErrProviderNotAllowed  = errors.New("model provider or model is not allowed")
	ErrOutputSchema        = errors.New("model output does not satisfy response schema")
	ErrCredentialDetected  = errors.New("credential-like content rejected")
)
