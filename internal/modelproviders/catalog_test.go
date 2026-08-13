package modelproviders

import "testing"

func TestOpenAIModelsUseConfiguredMaxInput(t *testing.T) {
	provider, found := findCatalog(ProviderOpenAI)
	if !found {
		t.Fatal("OpenAI catalog is missing")
	}
	for _, model := range provider.Models {
		if model.MaxInput != 258_000 || model.ContextWindow != 400_000 {
			t.Fatalf("model %q limits = max input %d, context window %d; want 258000 and 400000", model.ID, model.MaxInput, model.ContextWindow)
		}
	}
}
