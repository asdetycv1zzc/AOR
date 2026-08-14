// Package mockenv exposes the process-wide mock environment switch.
package mockenv

import (
	"os"
	"strings"
)

// Enabled is initialized from AOR_MOCK_ENVIRONMENT and may be overridden by
// tests before constructing services.
var Enabled = enabledValue(os.Getenv("AOR_MOCK_ENVIRONMENT"))

func enabledValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
