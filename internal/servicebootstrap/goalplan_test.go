package servicebootstrap

import (
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

func TestConfiguredGoalPlanRoutesBindEveryRequiredRole(t *testing.T) {
	seed := int64(7)
	configured := runtimeconfig.GoalPlanRouteConfig{
		Provider: "provider", Model: "model", MaxOutputTokens: 4096, Temperature: 0,
		Seed: &seed, ProviderPolicy: "default", CachePolicy: "NO_STORE", MaxAttempts: 3,
	}
	routes, err := configuredGoalPlanRoutes(runtimeconfig.GoalPlanConfig{Routes: map[string]runtimeconfig.GoalPlanRouteConfig{
		"GOAL_PROPOSER": configured, "GOAL_CHALLENGER": configured,
		"PLAN_SUPERVISOR": configured, "MODULE_PLANNER": configured,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []agentruntime.Role{
		agentruntime.RoleGoalProposer, agentruntime.RoleGoalChallenger,
		agentruntime.RolePlanSupervisor, agentruntime.RoleModulePlanner,
	} {
		route, found := routes[role]
		if !found || route.Provider != configured.Provider || route.Model != configured.Model || route.Seed == nil || *route.Seed != seed || route.MaxAttempts != 3 {
			t.Fatalf("route %s = %#v", role, route)
		}
	}
	seed = 9
	if *routes[agentruntime.RoleGoalProposer].Seed != 7 {
		t.Fatal("route retained caller-owned seed pointer")
	}
}

func TestConfiguredGoalPlanRoutesRejectMissingRole(t *testing.T) {
	_, err := configuredGoalPlanRoutes(runtimeconfig.GoalPlanConfig{Routes: map[string]runtimeconfig.GoalPlanRouteConfig{
		"GOAL_PROPOSER": {},
	}})
	if !errors.Is(err, runtimeconfig.ErrInvalidConfiguration) {
		t.Fatalf("error = %v", err)
	}
}
