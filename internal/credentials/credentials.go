package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
)

type Pattern struct {
	Name string
	RE   *regexp.Regexp
}

// Match identifies a credential-shaped span without retaining its value.
// Offsets are byte offsets into the scanned UTF-8 string.
type Match struct {
	Name        string
	Start       int
	End         int
	Fingerprint string
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

// Scan returns stable, content-free fingerprints for every credential-shaped
// match. The fingerprint is useful for correlating security events while the
// secret itself remains unavailable to callers.
func Scan(value string) []Match {
	return scanBytes([]byte(value))
}

// ScanBytes is the byte-oriented form used by repository scanners.
func ScanBytes(value []byte) []Match {
	return scanBytes(value)
}

func scanBytes(value []byte) []Match {
	matches := make([]Match, 0)
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		for _, index := range pattern.RE.FindAllIndex(value, -1) {
			if len(index) != 2 || index[0] < 0 || index[1] <= index[0] || index[1] > len(value) {
				continue
			}
			fingerprint := Fingerprint(string(value[index[0]:index[1]]))
			key := pattern.Name + "\x00" + strconv.Itoa(index[0]) + "\x00" + strconv.Itoa(index[1]) + "\x00" + fingerprint
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, Match{Name: pattern.Name, Start: index[0], End: index[1], Fingerprint: fingerprint})
		}
	}
	return matches
}

// Fingerprint returns a one-way digest suitable for correlation and audit
// records. It is deliberately not a reversible encoding of the value.
func Fingerprint(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func Contains(value string) bool {
	return len(Scan(value)) > 0
}

func Redact(value, replacement string) (string, bool) {
	redacted := value
	changed := false
	for _, pattern := range patterns {
		next := pattern.RE.ReplaceAllStringFunc(redacted, func(string) string { return replacement })
		changed = changed || next != redacted
		redacted = next
	}
	return redacted, changed
}
