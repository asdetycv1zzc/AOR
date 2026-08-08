package servicebootstrap

import (
	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/controlapi"
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
		configured, found := config.GoalPlan.Routes[string(role)]
		if !found {
			return nil, nil, runtimeconfig.ErrInvalidConfiguration
		}
		routes[string(role)] = projectModelRoute(configured)
	}
	routes[string(agentruntime.RoleExecutor)] = projectModelRoute(config.Execution.Route)
	moduleAuditor := config.ModuleAuditRoute
	if moduleAuditor.Provider == "" {
		moduleAuditor = config.Execution.Route
	}
	routes[string(agentruntime.RoleModuleAuditor)] = projectModelRoute(moduleAuditor)
	globalAuditor := config.GlobalAuditRoute
	if globalAuditor.Provider == "" {
		globalAuditor = moduleAuditor
	}
	routes[string(agentruntime.RoleGlobalAuditor)] = projectModelRoute(globalAuditor)
	if state.ValidateProjectModelRoutes(routes) != nil {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}

	providers := make([]controlapi.ModelProvider, 0, len(config.ModelGateway.Providers))
	for _, provider := range config.ModelGateway.Providers {
		providers = append(providers, controlapi.ModelProvider{
			ID: provider.ID, Provider: provider.Provider, Models: append([]string(nil), provider.Models...),
			ReasoningEffort:     provider.ReasoningEffort,
			InputMicrosPerToken: provider.InputMicrosPerToken, OutputMicrosPerToken: provider.OutputMicrosPerToken,
			SupportsStreaming: provider.SupportsStreaming, SupportsToolCalls: provider.SupportsToolCalls,
			SupportsJSONSchema: provider.SupportsJSONSchema, SupportsSeed: provider.SupportsSeed,
			SupportsPromptCaching: provider.SupportsPromptCaching,
			MaxInputTokens:        provider.MaxInputTokens, MaxOutputTokens: provider.MaxOutputTokens,
			AllowedDataClassifications: append([]string(nil), provider.AllowedDataClassifications...),
			DataResidency:              append([]string(nil), provider.DataResidency...), RetentionPolicy: provider.RetentionPolicy,
			Modalities: append([]string(nil), provider.Modalities...),
		})
	}
	if len(providers) == 0 {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}
	return providers, routes, nil
}

func projectModelRoute(route runtimeconfig.GoalPlanRouteConfig) state.ProjectModelRoute {
	var seed *int64
	if route.Seed != nil {
		value := *route.Seed
		seed = &value
	}
	return state.ProjectModelRoute{
		Provider: route.Provider, Model: route.Model, MaxOutputTokens: route.MaxOutputTokens,
		Temperature: route.Temperature, Seed: seed, ProviderPolicy: route.ProviderPolicy,
		CachePolicy: route.CachePolicy, WorstCaseCostMicros: route.WorstCaseCostMicros,
		MaxAttempts: route.MaxAttempts,
	}
}
