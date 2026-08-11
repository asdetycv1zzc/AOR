package servicebootstrap

import (
	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/controlapi"
	"github.com/akimisaka/aor/internal/modelproviders"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/state"
)

func configuredControlModelConfiguration(config runtimeconfig.Config) ([]controlapi.ModelProvider, map[string]state.ProjectModelRoute, error) {
	routes := make(map[string]state.ProjectModelRoute, 8)
	for _, role := range []agentruntime.Role{
		agentruntime.RoleGoalProposer,
		agentruntime.RoleGoalChallenger,
		agentruntime.RolePlanSupervisor,
		agentruntime.RoleModulePlanner,
		agentruntime.RoleKnowledgeCurator,
	} {
		routes[string(role)] = projectModelRoute(configuredRoleRoute(config, role))
	}
	routes[string(agentruntime.RoleExecutor)] = projectModelRoute(configuredRoleRoute(config, agentruntime.RoleExecutor))
	routes[string(agentruntime.RoleModuleAuditor)] = projectModelRoute(configuredRoleRoute(config, agentruntime.RoleModuleAuditor))
	routes[string(agentruntime.RoleGlobalAuditor)] = projectModelRoute(configuredRoleRoute(config, agentruntime.RoleGlobalAuditor))
	if state.ValidateProjectModelRoutes(routes) != nil {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}

	providers := make([]controlapi.ModelProvider, 0, len(modelproviders.Catalog()))
	for _, provider := range modelproviders.Catalog() {
		models := make([]string, 0, len(provider.Models))
		maxInputTokens, maxOutputTokens := 0, 0
		supportsStreaming, supportsToolCalls, supportsJSONSchema, supportsPromptCaching := true, true, true, true
		for _, model := range provider.Models {
			models = append(models, model.ID)
			if model.MaxInput > maxInputTokens {
				maxInputTokens = model.MaxInput
			}
			if model.MaxOutput > maxOutputTokens {
				maxOutputTokens = model.MaxOutput
			}
			supportsStreaming = supportsStreaming && model.Streaming
			supportsToolCalls = supportsToolCalls && model.ToolCalls
			supportsJSONSchema = supportsJSONSchema && model.JSONSchema
			supportsPromptCaching = supportsPromptCaching && model.PromptCache
		}
		providers = append(providers, controlapi.ModelProvider{
			ID: provider.ID, Provider: provider.ID, Models: models,
			InputMicrosPerToken: 1, OutputMicrosPerToken: 4,
			SupportsStreaming: supportsStreaming, SupportsToolCalls: supportsToolCalls,
			SupportsJSONSchema: supportsJSONSchema, SupportsPromptCaching: supportsPromptCaching,
			MaxInputTokens: maxInputTokens, MaxOutputTokens: maxOutputTokens,
			AllowedDataClassifications: []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
			DataResidency:              []string{"provider-defined"}, RetentionPolicy: "provider-defined",
			Modalities: []string{"text"},
		})
	}
	return providers, routes, nil
}

func configuredRoleRoute(config runtimeconfig.Config, role agentruntime.Role) runtimeconfig.GoalPlanRouteConfig {
	switch role {
	case agentruntime.RoleExecutor:
		if config.Execution.Route.Provider != "" {
			return config.Execution.Route
		}
	case agentruntime.RoleModuleAuditor:
		if config.ModuleAuditRoute.Provider != "" {
			return config.ModuleAuditRoute
		}
	case agentruntime.RoleGlobalAuditor:
		if config.GlobalAuditRoute.Provider != "" {
			return config.GlobalAuditRoute
		}
	}
	if route, found := config.GoalPlan.Routes[string(role)]; found {
		return route
	}
	return defaultRoleRoute(role)
}

func defaultRoleRoute(role agentruntime.Role) runtimeconfig.GoalPlanRouteConfig {
	provider, model, reasoningEffort := modelproviders.ProviderOpenAI, "gpt-5.6-sol", "medium"
	if role == agentruntime.RolePlanSupervisor || role == agentruntime.RoleModuleAuditor || role == agentruntime.RoleGlobalAuditor {
		provider, model, reasoningEffort = modelproviders.ProviderDeepSeek, "deepseek-v4-flash", "high"
	}
	return runtimeconfig.GoalPlanRouteConfig{
		Provider: provider, Model: model, ReasoningEffort: reasoningEffort, MaxOutputTokens: 4096, ThinkingBudget: 0, Temperature: 0,
		ProviderPolicy: "default", CachePolicy: "NO_STORE", MaxAttempts: 5,
	}
}

func projectModelRoute(route runtimeconfig.GoalPlanRouteConfig) state.ProjectModelRoute {
	var seed *int64
	if route.Seed != nil {
		value := *route.Seed
		seed = &value
	}
	return state.ProjectModelRoute{
		Provider: route.Provider, Model: route.Model, ReasoningEffort: route.ReasoningEffort, MaxOutputTokens: route.MaxOutputTokens,
		ThinkingBudget: route.ThinkingBudget,
		Temperature:    route.Temperature, Seed: seed, ProviderPolicy: route.ProviderPolicy,
		CachePolicy: route.CachePolicy, WorstCaseCostMicros: route.WorstCaseCostMicros,
		MaxAttempts: route.MaxAttempts,
	}
}
