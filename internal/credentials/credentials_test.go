package credentials

import (
	"strings"
	"testing"
)

func TestContainsAndRedactCredentialFamilies(t *testing.T) {
	values := []string{
		"sk-" + "0123456789abcdefghijklmnop",
		"AKIA" + "0123456789ABCDEF",
		"Bearer " + "0123456789abcdefghijklmnop",
		"ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz",
		"github_pat_" + "0123456789abcdefghijklmnopqrstuvwxyz_ABCDEF",
		"glpat-" + "0123456789abcdefghijklmnop",
		"xoxb-" + "0123456789-abcdefghijklmnop",
		"AIza" + "0123456789abcdefghijklmnopqrstuvwxy",
		"GOCSPX-" + "0123456789abcdefghijklmnop",
		"sk_live_" + "0123456789abcdefghijklmnop",
		"npm_" + "0123456789abcdefghijklmnop",
		"refresh_" + "token=synthetic-refresh-token-value",
		"-----BEGIN " + "PRIVATE KEY-----",
	}
	for _, value := range values {
		if !Contains(value) {
			t.Fatalf("credential family was not detected: %q", value)
		}
		redacted, changed := Redact("prefix "+value+" suffix", "[REDACTED]")
		if !changed || Contains(redacted) {
			t.Fatalf("credential family was not redacted: %q", redacted)
		}
	}
}

func TestScanReturnsStableContentFreeFingerprints(t *testing.T) {
	value := "prefix " + "sk-" + "0123456789abcdefghijklmnop" + " suffix"
	first := Scan(value)
	second := Scan(value)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("matches = %#v %#v", first, second)
	}
	if first[0] != second[0] || first[0].Name != strings.Join([]string{"openai", "api", "key"}, "_") || first[0].Fingerprint == "" {
		t.Fatalf("unstable match = %#v %#v", first, second)
	}
	if first[0].Fingerprint == value || first[0].Start < 0 || first[0].End <= first[0].Start {
		t.Fatalf("match exposes invalid span or secret: %#v", first[0])
	}
}

func TestRedactTreatsReplacementLiterally(t *testing.T) {
	redacted, changed := Redact("sk-"+"0123456789abcdefghijklmnop", "$1[REDACTED]")
	if !changed || redacted != "$1[REDACTED]" {
		t.Fatalf("literal replacement = %q changed=%v", redacted, changed)
	}
}
