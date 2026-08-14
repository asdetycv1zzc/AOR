package modelproviders

import (
	"context"
	"testing"

	"github.com/akimisaka/aor/internal/modelgateway"
)

func TestCapabilityOverrideOnlyChangesContextWindow(t *testing.T) {
	const model = modelgateway.CommandReviewModel
	adapter, err := (AdapterFactory{}).NewWithSettings(ResolvedSettings{
		ProviderSettings: ProviderSettings{
			Provider:                 ProviderOpenAI,
			BaseURL:                  "https://api.openai.com/v1",
			Protocol:                 ProtocolOpenAIResponses,
			Models:                   []string{model},
			ModelContextWindowTokens: map[string]int{model: 400_000},
		},
		APIKey: "test-key",
	})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	capabilities, err := adapter.Capabilities(context.Background(), model)
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if capabilities.ContextWindowTokens != 400_000 {
		t.Fatalf("context window = %d, want 400000", capabilities.ContextWindowTokens)
	}
	if capabilities.MaxInputTokens != 258_000 {
		t.Fatalf("max input = %d, want 258000", capabilities.MaxInputTokens)
	}
}
