package modelgateway

import "testing"

func TestNormalizeProviderReasoningEffort(t *testing.T) {
	if got := normalizeProviderReasoningEffort("deepseek", "max"); got != "high" {
		t.Fatalf("deepseek max effort = %q, want high", got)
	}
	if got := normalizeProviderReasoningEffort("deepseek-audit", "max"); got != "high" {
		t.Fatalf("deepseek-audit max effort = %q, want high", got)
	}
	for _, test := range []struct {
		provider string
		effort   string
	}{
		{provider: "openai", effort: "max"},
		{provider: "deepseek", effort: "high"},
		{provider: "deepseek", effort: "medium"},
	} {
		if got := normalizeProviderReasoningEffort(test.provider, test.effort); got != test.effort {
			t.Fatalf("normalizeProviderReasoningEffort(%q, %q) = %q", test.provider, test.effort, got)
		}
	}
}
