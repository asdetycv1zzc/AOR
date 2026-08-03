package credentials

import "regexp"

type Pattern struct {
	Name string
	RE   *regexp.Regexp
}

var patterns = []Pattern{
	{Name: "openai_api_key", RE: regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{16,}\b`)},
	{Name: "aws_access_key", RE: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{Name: "bearer_token", RE: regexp.MustCompile(`(?i)\bbearer[ \t]+[a-z0-9._~+/=-]{12,}`)},
	{Name: "github_token", RE: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{Name: "github_fine_grained_token", RE: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`)},
	{Name: "gitlab_token", RE: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{Name: "slack_token", RE: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{Name: "google_api_key", RE: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{Name: "google_oauth_secret", RE: regexp.MustCompile(`\bGOCSPX-[0-9A-Za-z_-]{20,}\b`)},
	{Name: "stripe_secret_key", RE: regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,}\b`)},
	{Name: "npm_token", RE: regexp.MustCompile(`\bnpm_[0-9A-Za-z]{20,}\b`)},
	{Name: "credential_assignment", RE: regexp.MustCompile(`(?i)\b(?:refresh[_-]?token|client[_-]?secret|access[_-]?token|api[_-]?key|password|passwd)\b[ \t]*[:=][ \t]*["']?[a-z0-9._~+/=-]{8,}`)},
	{Name: "private_key", RE: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
}

func Patterns() []Pattern {
	return append([]Pattern(nil), patterns...)
}

func Contains(value string) bool {
	for _, pattern := range patterns {
		if pattern.RE.MatchString(value) {
			return true
		}
	}
	return false
}

func Redact(value, replacement string) (string, bool) {
	redacted := value
	changed := false
	for _, pattern := range patterns {
		next := pattern.RE.ReplaceAllString(redacted, replacement)
		changed = changed || next != redacted
		redacted = next
	}
	return redacted, changed
}
