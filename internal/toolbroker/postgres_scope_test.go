package toolbroker

import (
	"context"
	"database/sql"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

func TestPostgresScopeResolverRequiresDatabaseAndDeploymentProfile(t *testing.T) {
	database := &sql.DB{}
	for _, profile := range []string{"", "DEVELOPMENT", "production"} {
		if _, err := NewPostgresScopeResolver(PostgresScopeResolverConfig{Database: database, DeploymentProfile: profile}); err == nil {
			t.Fatalf("profile %q was accepted", profile)
		}
	}
	if _, err := NewPostgresScopeResolver(PostgresScopeResolverConfig{DeploymentProfile: "PRODUCTION"}); err == nil {
		t.Fatal("nil database was accepted")
	}
	if _, err := NewPostgresScopeResolver(PostgresScopeResolverConfig{Database: database, DeploymentProfile: "PRODUCTION"}); err != nil {
		t.Fatalf("valid resolver error = %v", err)
	}
}

func TestDetachedPlanningScopeOnlyAllowsModulePlannerModelGeneration(t *testing.T) {
	query := ToolAuthorizationScopeQuery{
		ProjectID: "project-1", TaskID: "task-1", PrincipalID: "project-1:MODULE_PLANNER:task-1",
		Role: authn.RoleModulePlanner, Action: authz.ActionModelGenerate,
	}
	if !allowsDetachedPlanningScope(query) {
		t.Fatal("ModulePlanner model generation was rejected")
	}
	query.Action = authz.ActionToolInvoke
	if allowsDetachedPlanningScope(query) {
		t.Fatal("detached planning task accepted tool invocation")
	}
	query.Action = authz.ActionModelGenerate
	query.Role = authn.RoleExecutor
	if allowsDetachedPlanningScope(query) {
		t.Fatal("detached planning task accepted non-planner role")
	}
	query.Role = authn.RoleModulePlanner
	query.PrincipalID = "project-1:MODULE_PLANNER:other-task"
	if allowsDetachedPlanningScope(query) {
		t.Fatal("detached planning task accepted another task planner")
	}
}

func TestToolBudgetScopeMatchesAuthoritativeDimensions(t *testing.T) {
	query := ToolAuthorizationScopeQuery{ProjectID: "project-1", TaskID: "task-1", PrincipalID: "agent-1", Role: "EXECUTOR"}
	for _, match := range []struct {
		typeName string
		id       string
	}{
		{typeName: "PROJECT", id: "project-1"},
		{typeName: "TASK", id: "task-1"},
		{typeName: "AGENT", id: "agent-1"},
		{typeName: "ROLE", id: "EXECUTOR"},
	} {
		if !toolBudgetScopeMatches(match.typeName, match.id, query) {
			t.Fatalf("scope %s/%s did not match", match.typeName, match.id)
		}
	}
	if toolBudgetScopeMatches("PROVIDER", "project-1", query) || toolBudgetScopeMatches("TASK", "other", query) {
		t.Fatal("unrelated budget scope matched")
	}
}

func TestTrustedRequestScopeBindsAuthenticatedTenantAndProject(t *testing.T) {
	principal := authn.Principal{ID: "agent-1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant-1", ProjectID: "project-1"}
	ctx, err := authn.ContextWithPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if !trustedRequestScope(ctx, "tenant-1", "project-1") {
		t.Fatal("exact authenticated scope was rejected")
	}
	if trustedRequestScope(ctx, "tenant-2", "project-1") || trustedRequestScope(ctx, "tenant-1", "project-2") || trustedRequestScope(context.Background(), "tenant-1", "project-1") {
		t.Fatal("untrusted scope was accepted")
	}
}
