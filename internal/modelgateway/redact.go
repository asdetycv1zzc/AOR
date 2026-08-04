package modelgateway

import (
	"strings"

	"github.com/akimisaka/aor/internal/credentials"
)

func containsCredentialLike(value string) bool {
	return credentials.Contains(value)
}

func redactError(value error) error {
	if value == nil {
		return nil
	}
	message, _ := credentials.Redact(value.Error(), "[REDACTED]")
	return &gatewayError{message: message, cause: value}
}

type gatewayError struct {
	message string
	cause   error
}

func (e *gatewayError) Error() string { return strings.TrimSpace(e.message) }

func (e *gatewayError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
