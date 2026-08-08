package toolbroker

import (
	"context"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

// ToolAuthorizationScope is loaded from an authoritative control-plane
// projection. Project and Task state is never accepted from MCP request data.
type ToolAuthorizationScope struct {
	Project  authz.ProjectScope
	Task     authz.TaskScope
	Budget   authz.BudgetScope
	Approval *authz.Approval
}

type ToolAuthorizationScopeResolver interface {
	ResolveToolAuthorizationScope(context.Context, ToolAuthorizationScopeQuery) (ToolAuthorizationScope, error)
}

type ToolAuthorizationScopeQuery struct {
	TenantID        string
	ProjectID       string
	TaskID          string
	BudgetAccountID string
	ApprovalID      string
	PrincipalID     string
	Role            string
	Action          string
}

type AuthzPolicyEvaluator interface {
	Evaluate(context.Context, authz.PolicyInput) (authz.PolicyDecision, error)
}

// OPAPolicyEvaluator converts a broker invocation into the complete OPA input
// while sourcing mutable state and approval facts from a trusted resolver.
type OPAPolicyEvaluator struct {
	Policy AuthzPolicyEvaluator
	Scopes ToolAuthorizationScopeResolver
	Clock  func() time.Time
}

func (e OPAPolicyEvaluator) Evaluate(ctx context.Context, descriptor ToolDescriptor, request ToolRequest) (PolicyDecision, error) {
	if e.Policy == nil || e.Scopes == nil || ctx == nil {
		return PolicyDecision{}, ErrPolicyDenied
	}
	digest, err := canonicaljson.Digest(request.Parameters)
	if err != nil {
		return PolicyDecision{}, ErrPolicyDenied
	}
	scope, err := e.Scopes.ResolveToolAuthorizationScope(ctx, ToolAuthorizationScopeQuery{TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, BudgetAccountID: request.BudgetAccountID, ApprovalID: approvalID(request.Approval), PrincipalID: request.Principal.ID, Role: request.Principal.Role, Action: authz.ActionToolInvoke})
	if err != nil {
		return PolicyDecision{}, ErrPolicyDenied
	}
	if scope.Project.TenantID != request.TenantID || scope.Project.ID != request.ProjectID || scope.Task.TenantID != request.TenantID || scope.Task.ProjectID != request.ProjectID || scope.Task.ID != request.TaskID || scope.Budget.AccountID != request.BudgetAccountID || !scope.Budget.Available {
		return PolicyDecision{}, ErrPolicyDenied
	}
	expiresAt, err := time.Parse(time.RFC3339, request.Lease.ExpiresAt)
	if err != nil {
		return PolicyDecision{}, ErrLeaseInvalid
	}
	principal := authn.Principal{ID: request.Principal.ID, Type: authn.PrincipalType(request.Principal.Type), Role: request.Principal.Role, TenantID: request.TenantID, ProjectID: request.ProjectID}
	input := authz.PolicyInput{
		Principal:       principal,
		Project:         scope.Project,
		Task:            scope.Task,
		Action:          authz.ActionToolInvoke,
		Resource:        AuthorizationResource(descriptor.MCPServerID, descriptor.ToolID, descriptor.Version, request.ExecutionLeaseID),
		ParameterDigest: digest,
		Budget:          scope.Budget,
		Lease:           &authz.LeaseReference{ID: request.Lease.ID, ExpiresAt: expiresAt, PolicyVersion: request.PolicyVersion, FencingToken: request.Lease.FencingToken},
		Approval:        scope.Approval,
		Context:         authz.ExecutionContext{Platform: scope.Task.ExecutionPlatform, SandboxLevel: scope.Task.SandboxLevel},
	}
	decision, err := e.Policy.Evaluate(ctx, input)
	if err != nil || decision.Decision != authz.DecisionAllow || decision.PolicyVersion != request.PolicyVersion {
		return PolicyDecision{}, ErrPolicyDenied
	}
	return PolicyDecision{Allow: true, PolicyVersion: decision.PolicyVersion, ReasonCodes: append([]string(nil), decision.ReasonCodes...)}, nil
}

func (e OPAPolicyEvaluator) Revalidate(ctx context.Context, request ToolRequest, descriptor ToolDescriptor) error {
	decision, err := e.Evaluate(ctx, descriptor, request)
	if err != nil || !decision.Allow {
		return ErrPolicyDenied
	}
	return nil
}

func approvalID(approval *Approval) string {
	if approval == nil {
		return ""
	}
	return approval.ID
}

var _ PolicyEvaluator = OPAPolicyEvaluator{}
