package observability

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/credentials"
)

type Limits struct {
	MaxEventBytes          int
	MaxAttributes          int
	MaxAttributeKeyBytes   int
	MaxAttributeValueBytes int
}

func DefaultLimits() Limits {
	return Limits{
		MaxEventBytes:          64 * 1024,
		MaxAttributes:          64,
		MaxAttributeKeyBytes:   128,
		MaxAttributeValueBytes: 4 * 1024,
	}
}

func (l Limits) normalized() Limits {
	defaults := DefaultLimits()
	if l.MaxEventBytes <= 0 || l.MaxEventBytes > defaults.MaxEventBytes {
		l.MaxEventBytes = defaults.MaxEventBytes
	}
	if l.MaxAttributes <= 0 || l.MaxAttributes > defaults.MaxAttributes {
		l.MaxAttributes = defaults.MaxAttributes
	}
	if l.MaxAttributeKeyBytes <= 0 || l.MaxAttributeKeyBytes > defaults.MaxAttributeKeyBytes {
		l.MaxAttributeKeyBytes = defaults.MaxAttributeKeyBytes
	}
	if l.MaxAttributeValueBytes <= 0 || l.MaxAttributeValueBytes > defaults.MaxAttributeValueBytes {
		l.MaxAttributeValueBytes = defaults.MaxAttributeValueBytes
	}
	return l
}

var (
	attributeKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
	emailPattern        = regexp.MustCompile(`(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`)
	ipv4Pattern         = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	secretPatterns      = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:api[_-]?key|password|secret|refresh[_-]?token)[ \t]*[:=][ \t]*[^ ,;]+`),
	}
)

func sanitizeAttributes(input map[string]string, limits Limits) (map[string]string, int, error) {
	limits = limits.normalized()
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make(map[string]string, min(len(keys), limits.MaxAttributes))
	redacted := 0
	for _, key := range keys {
		if len(output) >= limits.MaxAttributes {
			redacted++
			continue
		}
		if len(key) > limits.MaxAttributeKeyBytes || !attributeKeyPattern.MatchString(key) {
			return nil, redacted, ErrInvalidAttribute
		}
		if forbiddenContentKey(key) {
			redacted++
			continue
		}
		value, changed := redactValue(input[key])
		if changed {
			redacted++
		}
		output[key] = truncateUTF8(value, limits.MaxAttributeValueBytes)
	}
	if redacted > 0 && len(output) < limits.MaxAttributes {
		output["aor.telemetry.redacted"] = "true"
	}
	return output, redacted, nil
}

func forbiddenContentKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.Contains(normalized, "authorization") || strings.Contains(normalized, "credential") || strings.Contains(normalized, "cookie") || strings.Contains(normalized, "secret") {
		return true
	}
	if strings.Contains(normalized, "hidden_test") || strings.Contains(normalized, "pii") || strings.Contains(normalized, "personal_data") {
		return true
	}
	if strings.Contains(normalized, "prompt") && !hasSafeMetadataSuffix(normalized) {
		return true
	}
	if normalized == "error.code" || normalized == "status.code" || normalized == "http.response.status_code" || normalized == "rpc.grpc.status_code" {
		return false
	}
	if strings.Contains(normalized, "source") || strings.Contains(normalized, "code") {
		return !hasSafeMetadataSuffix(normalized)
	}
	if strings.Contains(normalized, "tool") && containsBodyToken(normalized) {
		return true
	}
	if strings.Contains(normalized, "model") && containsBodyToken(normalized) && !strings.HasSuffix(normalized, ".model") {
		return true
	}
	return false
}

func hasSafeMetadataSuffix(key string) bool {
	for _, suffix := range []string{".version", "_version", ".digest", "_digest", ".hash", "_hash", ".id", "_id", ".path", "_path", ".size", "_size"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func containsBodyToken(key string) bool {
	for _, token := range []string{"input", "output", "request", "response", "body", "content", "text", "completion"} {
		if strings.Contains(key, token) {
			return true
		}
	}
	return false
}

func redactValue(value string) (string, bool) {
	redacted, changed := credentials.Redact(value, "[REDACTED_SECRET]")
	for _, pattern := range secretPatterns {
		next := pattern.ReplaceAllString(redacted, "[REDACTED_SECRET]")
		changed = changed || next != redacted
		redacted = next
	}
	for _, pattern := range []*regexp.Regexp{emailPattern, ipv4Pattern} {
		next := pattern.ReplaceAllString(redacted, "[REDACTED_PII]")
		changed = changed || next != redacted
		redacted = next
	}
	return redacted, changed
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
