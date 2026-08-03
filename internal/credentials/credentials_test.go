package credentials

import "testing"

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
