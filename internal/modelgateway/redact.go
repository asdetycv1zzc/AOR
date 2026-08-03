package modelgateway

import (
	"regexp"
	"strings"
)

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{16,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9._-]{16,}`),
}

func containsCredentialLike(value string) bool {
	for _, pattern := range credentialPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func redactError(value error) error {
	if value == nil {
		return nil
	}
	message := value.Error()
	for _, pattern := range credentialPatterns {
		message = pattern.ReplaceAllString(message, "[REDACTED]")
	}
	return &gatewayError{message: message}
}

type gatewayError struct{ message string }

func (e *gatewayError) Error() string { return strings.TrimSpace(e.message) }
