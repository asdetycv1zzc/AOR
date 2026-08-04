// Package leaseauthority issues and maintains capability leases from current,
// tenant-scoped control-plane facts.
package leaseauthority

import (
	"context"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type Scope struct {
	Project  authz.ProjectScope
	Task     authz.TaskScope
	Budget   authz.BudgetScope
	Approval *authz.Approval
}

type ScopeQuery struct {
	TenantID        string
	ProjectID       string
	TaskID          string
	BudgetAccountID string
	ApprovalID      string
	PrincipalID     string
	Role            string
}

type ScopeResolver interface {
	Resolve(context.Context, ScopeQuery) (Scope, error)
}

type Manager interface {
	Issue(context.Context, authz.LeaseRequest) (authz.CapabilityLease, error)
	Renew(context.Context, authz.LeaseRenewalRequest) (authz.CapabilityLease, error)
	Heartbeat(context.Context, authz.LeaseHeartbeatRequest) (authz.CapabilityLease, error)
	Revoke(context.Context, authz.LeaseRevokeRequest) error
}

type Service struct {
	manager Manager
	policy  authz.LeaseGrantEvaluator
	scopes  ScopeResolver
	clock   func() time.Time
}

type Config struct {
	Manager Manager
	Policy  authz.LeaseGrantEvaluator
	Scopes  ScopeResolver
	Clock   func() time.Time
}

type GrantRequest struct {
	TenantID        string
	ProjectID       string
	TaskID          string
	Action          string
	Resource        authz.Resource
	ParameterDigest string
	BudgetAccountID string
	ApprovalID      string
	TTL             time.Duration
}

type RenewRequest struct {
	GrantRequest
	LeaseID       string
	FencingToken  int64
	PolicyVersion string
}

type HeartbeatRequest struct {
	TenantID     string
	LeaseID      string
	FencingToken int64
}

type RevokeRequest struct {
	LeaseID string
	Reason  string
}

func New(config Config) (*Service, error) {
	if config.Manager == nil || config.Policy == nil || config.Scopes == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease authority configuration"})
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{manager: config.Manager, policy: config.Policy, scopes: config.Scopes, clock: config.Clock}, nil
}

func (service *Service) Issue(ctx context.Context, principal authn.Principal, request GrantRequest) (authz.CapabilityLease, error) {
	input, grant, err := service.authorizeGrant(ctx, principal, request)
	if err != nil {
		return authz.CapabilityLease{}, err
	}
	return service.manager.Issue(ctx, authz.LeaseRequest{
		AgentInstanceID: principal.ID, Principal: principal,
		TenantID: input.Project.TenantID, ProjectID: input.Project.ID,
		ProjectVersion: input.Project.StateVersion, TaskID: input.Task.ID,
		TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest,
		Role: principal.Role, Action: input.Action, Resource: input.Resource,
		ParameterDigest: input.ParameterDigest, Capabilities: []string{input.Action},
		PolicyVersion: grant.PolicyVersion, BudgetAccountID: input.Budget.AccountID,
		TTL: request.TTL, Grant: grant,
	})
}

func (service *Service) Renew(ctx context.Context, principal authn.Principal, request RenewRequest) (authz.CapabilityLease, error) {
	if request.LeaseID == "" || request.FencingToken < 1 || request.PolicyVersion == "" {
		return authz.CapabilityLease{}, invalidRequest()
	}
	_, grant, err := service.authorizeGrant(ctx, principal, request.GrantRequest)
	if err != nil {
		return authz.CapabilityLease{}, err
	}
	if grant.PolicyVersion != request.PolicyVersion {
		return authz.CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease policy version"})
	}
	return service.manager.Renew(ctx, authz.LeaseRenewalRequest{
		LeaseID: request.LeaseID, TenantID: request.TenantID,
		FencingToken: request.FencingToken, PrincipalID: principal.ID,
		PrincipalType: principal.Type, Role: principal.Role,
		PolicyVersion: request.PolicyVersion, TTL: request.TTL, Grant: grant,
	})
}

func (service *Service) Heartbeat(ctx context.Context, principal authn.Principal, request HeartbeatRequest) (authz.CapabilityLease, error) {
	if err := service.validateCaller(ctx, principal, request.TenantID, ""); err != nil || request.LeaseID == "" || request.FencingToken < 1 {
		if err != nil {
			return authz.CapabilityLease{}, err
		}
		return authz.CapabilityLease{}, invalidRequest()
	}
	return service.manager.Heartbeat(ctx, authz.LeaseHeartbeatRequest{
		LeaseID: request.LeaseID, TenantID: request.TenantID,
		PrincipalID: principal.ID, FencingToken: request.FencingToken,
	})
}

func (service *Service) Revoke(ctx context.Context, principal authn.Principal, request RevokeRequest) error {
	if err := service.validateCaller(ctx, principal, principal.TenantID, principal.ProjectID); err != nil {
		return err
	}
	if request.LeaseID == "" {
		return invalidRequest()
	}
	return service.manager.Revoke(ctx, authz.LeaseRevokeRequest{LeaseID: request.LeaseID, Actor: principal, Reason: request.Reason})
}

func (service *Service) authorizeGrant(ctx context.Context, principal authn.Principal, request GrantRequest) (authz.PolicyInput, authz.PolicyDecision, error) {
	if service == nil || service.manager == nil || service.policy == nil || service.scopes == nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := service.validateCaller(ctx, principal, request.TenantID, request.ProjectID); err != nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, err
	}
	if request.TaskID == "" || request.Action == "" || request.ParameterDigest == "" || request.BudgetAccountID == "" || request.TTL < 0 {
		return authz.PolicyInput{}, authz.PolicyDecision{}, invalidRequest()
	}
	scope, err := service.scopes.Resolve(ctx, ScopeQuery{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		BudgetAccountID: request.BudgetAccountID, ApprovalID: request.ApprovalID,
		PrincipalID: principal.ID, Role: principal.Role,
	})
	if err != nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, aorerrors.Wrap(aorerrors.CodePolicyDenied, "", err, map[string]any{"scope": "lease authority"})
	}
	if scope.Project.TenantID != request.TenantID || scope.Project.ID != request.ProjectID || scope.Task.TenantID != request.TenantID || scope.Task.ProjectID != request.ProjectID || scope.Task.ID != request.TaskID || scope.Budget.AccountID != request.BudgetAccountID || !scope.Budget.Available {
		return authz.PolicyInput{}, authz.PolicyDecision{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "authoritative lease facts"})
	}
	input := authz.PolicyInput{
		Principal: principal, Project: scope.Project, Task: scope.Task,
		Action: request.Action, Resource: request.Resource,
		ParameterDigest: request.ParameterDigest, Budget: scope.Budget,
		Approval: scope.Approval,
		Context:  authz.ExecutionContext{Platform: scope.Task.ExecutionPlatform, SandboxLevel: scope.Task.SandboxLevel},
	}
	if err := input.Validate(service.clock().UTC()); err != nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, err
	}
	decision, err := service.policy.EvaluateLeaseGrant(ctx, input)
	if err != nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, err
	}
	if decision.Decision != authz.DecisionAllow || decision.Binding == nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": decision.PolicyVersion})
	}
	return input, decision, nil
}

func (service *Service) validateCaller(ctx context.Context, principal authn.Principal, tenantID, projectID string) error {
	if service == nil || ctx == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := principal.Validate(); err != nil {
		return err
	}
	current, ok := authn.PrincipalFromContext(ctx)
	if !ok || current.ID != principal.ID || current.Type != principal.Type || current.Role != principal.Role || current.TenantID != principal.TenantID || current.ProjectID != principal.ProjectID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease caller"})
	}
	if tenantID == "" || principal.TenantID != "" && principal.TenantID != tenantID || projectID != "" && principal.ProjectID != "" && principal.ProjectID != projectID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease tenant project"})
	}
	return nil
}

func invalidRequest() error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease request"})
}
