package servicebootstrap

import (
	"context"
	"os"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/controlapi"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/knowledgecurator"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
)

const goalPlanAgentLimit = 8

type configuredProjectAgents struct {
	goalPlan controlapi.GoalPlanServices
	curator  *knowledgecurator.Service
}

func configuredGoalPlanServices(config runtimeconfig.Config, store *aorworkflow.ProjectLifecycleStore, leases *leaseauthority.Service, authorizer authz.PolicyEvaluator, knowledgeService knowledgecurator.KnowledgeService, knowledgeUpdates knowledge.KnowledgeUpdatedLookup) (configuredProjectAgents, error) {
	if store == nil || leases == nil || authorizer == nil || knowledgeService == nil || knowledgeUpdates == nil {
		return configuredProjectAgents{}, runtimeconfig.ErrInvalidConfiguration
	}
	routes, err := configuredGoalPlanRoutes(config.GoalPlan)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	resolveContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	gateway, err := configuredModelGatewayClient(resolveContext, config, credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT")))
	cancel()
	if err != nil {
		return configuredProjectAgents{}, err
	}
	boundary, err := controlapi.NewPolicyCommitBoundary(authorizer)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	projects := orchestrator.NewWithBoundary(store, time.Now, boundary)
	artifacts, err := goalplan.NewEventArtifactStore(store, time.Now)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	runtimeAuthority, err := leaseauthority.NewRuntimeAuthority(leases, 5*time.Minute)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	slots, err := agentruntime.NewSlotPool(goalPlanAgentLimit, time.Now)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	runtime, err := agentruntime.New(runtimeAuthority, gateway, nil, slots, time.Now)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	preparer, err := goalplan.NewAuthoritativeRuntimePreparer(goalplan.RuntimePreparerConfig{
		Artifacts: artifacts, Projects: projects, Tasks: projects, Leases: leases,
		Routes: routes, LeaseTTL: 5 * time.Minute, Clock: time.Now,
	})
	if err != nil {
		return configuredProjectAgents{}, err
	}
	invoker, err := goalplan.NewRuntimeAgentInvoker(runtime, preparer)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	negotiator, err := goalplan.NewNegotiator(artifacts, invoker, projects, time.Now)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	planner, err := goalplan.NewPlanner(artifacts, invoker, projects, time.Now)
	if err != nil {
		return configuredProjectAgents{}, err
	}
	curator, err := knowledgecurator.New(knowledgecurator.Config{
		Store: store, Updates: knowledgeUpdates, Artifacts: artifacts, Projects: projects, Knowledge: knowledgeService,
		Invoker: invoker, Leases: leases, Clock: time.Now, LeaseTTL: 5 * time.Minute,
	})
	if err != nil {
		return configuredProjectAgents{}, err
	}
	return configuredProjectAgents{
		goalPlan: controlapi.GoalPlanServices{Negotiator: negotiator, Planner: planner},
		curator:  curator,
	}, nil
}

func configuredGoalPlanRoutes(config runtimeconfig.GoalPlanConfig) (map[agentruntime.Role]goalplan.ModelRoute, error) {
	roles := []agentruntime.Role{
		agentruntime.RoleGoalProposer,
		agentruntime.RoleGoalChallenger,
		agentruntime.RolePlanSupervisor,
		agentruntime.RoleModulePlanner,
		agentruntime.RoleKnowledgeCurator,
	}
	if len(config.Routes) != len(roles) {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	routes := make(map[agentruntime.Role]goalplan.ModelRoute, len(roles))
	for _, role := range roles {
		configured, found := config.Routes[string(role)]
		if !found {
			return nil, runtimeconfig.ErrInvalidConfiguration
		}
		var seed *int64
		if configured.Seed != nil {
			value := *configured.Seed
			seed = &value
		}
		routes[role] = goalplan.ModelRoute{
			Provider: configured.Provider, Model: configured.Model,
			MaxOutputTokens: configured.MaxOutputTokens, Temperature: configured.Temperature, Seed: seed,
			ProviderPolicy: configured.ProviderPolicy, CachePolicy: configured.CachePolicy,
			WorstCaseCostMicros: configured.WorstCaseCostMicros, MaxAttempts: configured.MaxAttempts,
		}
	}
	return routes, nil
}
