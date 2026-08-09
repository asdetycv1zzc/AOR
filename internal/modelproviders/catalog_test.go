package modelproviders

import "testing"

func TestCatalogContainsRequiredProviderFamilies(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != 4 {
		t.Fatalf("provider count = %d", len(catalog))
	}
	for _, expected := range []struct{ provider, model string }{
		{ProviderOpenAI, "gpt-5.4"},
		{ProviderOpenAI, "gpt-5.6-sol"},
		{ProviderDeepSeek, "deepseek-v4-pro"},
		{ProviderDeepSeek, "deepseek-v4-flash"},
		{ProviderClaude, "claude-sonnet-4-6"},
		{ProviderClaude, "claude-opus-4-6"},
		{ProviderClaude, "claude-fable-4-6"},
		{ProviderGrok, "grok-4.5"},
	} {
		if _, found := findModel(expected.provider, expected.model); !found {
			t.Errorf("missing %s/%s", expected.provider, expected.model)
		}
	}
	claude, _ := findCatalog(ProviderClaude)
	if !validProtocol(claude, ProtocolAnthropic) || !validProtocol(claude, ProtocolOpenAICompatible) {
		t.Fatal("Claude protocols are incomplete")
	}
}
