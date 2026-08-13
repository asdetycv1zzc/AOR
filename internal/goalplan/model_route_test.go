package goalplan

import (
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/state"
)

func TestResolveProjectModelRouteFillsLegacyContextWindowFromMatchingFallback(t *testing.T) {
	configured := state.ProjectModelRoute{
		Provider: "openai", Model: "gpt-5.4", ReasoningEffort: "medium", MaxOutputTokens: 128,
		ProviderPolicy: "default", CachePolicy: "local", MaxAttempts: 1,
	}
	project := state.Project{ModelRoutes: map[string]state.ProjectModelRoute{string(agentruntime.RoleGoalProposer): configured}}
	fallback := ModelRoute{
		Provider: "openai", Model: "gpt-5.4", ReasoningEffort: "medium", ContextWindowTokens: 400_000,
		MaxOutputTokens: 128, ProviderPolicy: "default", CachePolicy: "local", MaxAttempts: 1,
	}

	route, ok := ResolveProjectModelRoute(project, agentruntime.RoleGoalProposer, fallback)
	if !ok || route.ContextWindowTokens != fallback.ContextWindowTokens {
		t.Fatalf("resolved route = %#v, ok = %t", route, ok)
	}
}
