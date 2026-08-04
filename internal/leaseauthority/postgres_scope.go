package leaseauthority

import (
	"context"
	"database/sql"

	"github.com/akimisaka/aor/internal/toolbroker"
)

type PostgresScopeResolver struct {
	resolver *toolbroker.PostgresScopeResolver
}

func NewPostgresScopeResolver(database *sql.DB, deploymentProfile string) (*PostgresScopeResolver, error) {
	resolver, err := toolbroker.NewPostgresScopeResolver(toolbroker.PostgresScopeResolverConfig{Database: database, DeploymentProfile: deploymentProfile})
	if err != nil {
		return nil, err
	}
	return &PostgresScopeResolver{resolver: resolver}, nil
}

func (resolver *PostgresScopeResolver) Resolve(ctx context.Context, query ScopeQuery) (Scope, error) {
	if resolver == nil || resolver.resolver == nil {
		return Scope{}, toolbroker.ErrPolicyDenied
	}
	scope, err := resolver.resolver.ResolveToolAuthorizationScope(ctx, toolbroker.ToolAuthorizationScopeQuery{
		TenantID: query.TenantID, ProjectID: query.ProjectID, TaskID: query.TaskID,
		BudgetAccountID: query.BudgetAccountID, ApprovalID: query.ApprovalID,
		PrincipalID: query.PrincipalID, Role: query.Role,
	})
	if err != nil {
		return Scope{}, err
	}
	return Scope{Project: scope.Project, Task: scope.Task, Budget: scope.Budget, Approval: scope.Approval}, nil
}

var _ ScopeResolver = (*PostgresScopeResolver)(nil)
