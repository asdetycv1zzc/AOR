package goalplan

import (
	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/state"
)

// ResolveProjectModelRoute selects the immutable project route and falls back
// only for projects created before route snapshots were stored.
func ResolveProjectModelRoute(project state.Project, role agentruntime.Role, fallback ModelRoute) (ModelRoute, bool) {
	if !role.Valid() {
		return ModelRoute{}, false
	}
	configured, found := project.ModelRoutes[string(role)]
	if !found {
		if len(project.ModelRoutes) != 0 {
			return ModelRoute{}, false
		}
		if fallback.ReasoningEffort == "" {
			fallback.ReasoningEffort = state.DefaultModelReasoningEffort(fallback.Provider)
		}
		if !validModelRoute(fallback) {
			return ModelRoute{}, false
		}
		return cloneProjectModelRoute(fallback), true
	}
	route := ModelRoute{
		Provider:            configured.Provider,
		Model:               configured.Model,
		ReasoningEffort:     configured.ReasoningEffort,
		MaxOutputTokens:     configured.MaxOutputTokens,
		Temperature:         configured.Temperature,
		Seed:                configured.Seed,
		ProviderPolicy:      configured.ProviderPolicy,
		CachePolicy:         configured.CachePolicy,
		WorstCaseCostMicros: configured.WorstCaseCostMicros,
		MaxAttempts:         configured.MaxAttempts,
	}
	if route.ReasoningEffort == "" {
		route.ReasoningEffort = state.DefaultModelReasoningEffort(route.Provider)
	}
	if !validModelRoute(route) {
		return ModelRoute{}, false
	}
	return cloneProjectModelRoute(route), true
}

func cloneProjectModelRoute(route ModelRoute) ModelRoute {
	if route.Seed != nil {
		seed := *route.Seed
		route.Seed = &seed
	}
	return route
}
