// Package leaseauthority issues and maintains capability leases from current,
// tenant-scoped control-plane facts.
package leaseauthority

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
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
	Action          string
}

type ScopeResolver interface {
	Resolve(context.Context, ScopeQuery) (Scope, error)
}

type Manager interface {
	Issue(context.Context, authz.LeaseRequest) (authz.CapabilityLease, error)
	Renew(context.Context, authz.LeaseRenewalRequest) (authz.CapabilityLease, error)
	Heartbeat(context.Context, authz.LeaseHeartbeatRequest) (authz.CapabilityLease, error)
	Revoke(context.Context, authz.LeaseRevokeRequest) error
	GetForTenant(context.Context, string, string) (authz.CapabilityLease, bool, error)
	GetByIdempotency(context.Context, string, string, string) (authz.CapabilityLease, bool, error)
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
	IdempotencyKey  string
	TTL             time.Duration
	NotAfter        time.Time
}

type RenewRequest struct {
	GrantRequest
	LeaseID       string
	FencingToken  int64
	PolicyVersion string
}

type HeartbeatRequest struct {
	TenantID     string
	ProjectID    string
	TaskID       string
	LeaseID      string
	FencingToken int64
}

type RevokeRequest struct {
	TenantID       string
	ProjectID      string
	TaskID         string
	LeaseID        string
	Reason         string
	IdempotencyKey string
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
	return service.issue(ctx, principal, request, 0)
}

// IssueExecution creates the stable model-bound lease for one task execution.
// It is an internal scheduler boundary and is not exposed through the lease API.
func (service *Service) IssueExecution(ctx context.Context, principal authn.Principal, request GrantRequest, fencingToken int64) (authz.CapabilityLease, error) {
	if request.Action != authz.ActionModelGenerate || fencingToken < 1 {
		return authz.CapabilityLease{}, invalidRequest()
	}
	return service.issue(ctx, principal, request, fencingToken)
}

func (service *Service) issueAtFencing(ctx context.Context, principal authn.Principal, request GrantRequest, fencingToken int64) (authz.CapabilityLease, error) {
	if fencingToken < 1 {
		return authz.CapabilityLease{}, invalidRequest()
	}
	return service.issue(ctx, principal, request, fencingToken)
}

func (service *Service) issue(ctx context.Context, principal authn.Principal, request GrantRequest, fencingToken int64) (authz.CapabilityLease, error) {
	input, grant, err := service.authorizeGrant(ctx, principal, request)
	if err != nil {
		return authz.CapabilityLease{}, err
	}
	requestDigest, err := grantRequestDigest(principal, input, grant, request)
	if err != nil {
		return authz.CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeInvalidArgument, "", err, map[string]any{"scope": "lease idempotency"})
	}
	if existing, found, lookupErr := service.manager.GetByIdempotency(ctx, request.TenantID, principal.ID, request.IdempotencyKey); lookupErr != nil {
		return authz.CapabilityLease{}, lookupErr
	} else if found {
		if existing.Nonce == requestDigest && (fencingToken == 0 || existing.FencingToken == fencingToken) {
			return existing, nil
		}
		return authz.CapabilityLease{}, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", map[string]any{"scope": "lease issue"})
	}
	leaseID, idErr := uuid.NewV7()
	if idErr != nil {
		return authz.CapabilityLease{}, idErr
	}
	lease, issueErr := service.manager.Issue(ctx, authz.LeaseRequest{
		ID: leaseID.String(), IdempotencyKey: request.IdempotencyKey,
		AgentInstanceID: principal.ID, Principal: principal,
		TenantID: input.Project.TenantID, ProjectID: input.Project.ID,
		ProjectVersion: input.Project.StateVersion, TaskID: input.Task.ID,
		TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest,
		Role: principal.Role, Action: input.Action, Resource: input.Resource,
		ParameterDigest: input.ParameterDigest, Capabilities: []string{input.Action},
		PolicyVersion: grant.PolicyVersion, BudgetAccountID: input.Budget.AccountID,
		TTL: request.TTL, NotAfter: request.NotAfter, Grant: grant, RequestDigest: requestDigest, FencingToken: fencingToken,
	})
	if issueErr == nil {
		return lease, nil
	}
	existing, found, lookupErr := service.manager.GetByIdempotency(ctx, request.TenantID, principal.ID, request.IdempotencyKey)
	if lookupErr == nil && found && existing.Nonce == requestDigest && (fencingToken == 0 || existing.FencingToken == fencingToken) {
		return existing, nil
	}
	return authz.CapabilityLease{}, issueErr
}

func (service *Service) Renew(ctx context.Context, principal authn.Principal, request RenewRequest) (authz.CapabilityLease, error) {
	if request.LeaseID == "" || request.FencingToken < 1 || request.PolicyVersion == "" {
		return authz.CapabilityLease{}, invalidRequest()
	}
	input, grant, err := service.authorizeGrant(ctx, principal, request.GrantRequest)
	if err != nil {
		return authz.CapabilityLease{}, err
	}
	if grant.PolicyVersion != request.PolicyVersion {
		return authz.CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease policy version"})
	}
	requestDigest, err := grantRequestDigest(principal, input, grant, request.GrantRequest)
	if err != nil {
		return authz.CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeInvalidArgument, "", err, map[string]any{"scope": "lease idempotency"})
	}
	current, found, err := service.manager.GetForTenant(ctx, request.TenantID, request.LeaseID)
	if err != nil {
		return authz.CapabilityLease{}, err
	}
	if !found {
		return authz.CapabilityLease{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	preserveFencing := request.GrantRequest.Action == authz.ActionModelGenerate && request.GrantRequest.TaskID != ""
	expectedFencing := request.FencingToken + 1
	if preserveFencing {
		expectedFencing = request.FencingToken
	}
	if current.FencingToken == expectedFencing && current.Nonce == requestDigest {
		return current, nil
	}
	renewed, renewErr := service.manager.Renew(ctx, authz.LeaseRenewalRequest{
		LeaseID: request.LeaseID, TenantID: request.TenantID,
		FencingToken: request.FencingToken, PrincipalID: principal.ID,
		PrincipalType: principal.Type, Role: principal.Role,
		PolicyVersion: request.PolicyVersion, TTL: request.TTL, Grant: grant,
		RequestDigest:   requestDigest,
		PreserveFencing: preserveFencing,
	})
	if renewErr == nil {
		return renewed, nil
	}
	current, found, lookupErr := service.manager.GetForTenant(ctx, request.TenantID, request.LeaseID)
	if lookupErr == nil && found && current.FencingToken == expectedFencing && current.Nonce == requestDigest {
		return current, nil
	}
	return authz.CapabilityLease{}, renewErr
}

func (service *Service) Heartbeat(ctx context.Context, principal authn.Principal, request HeartbeatRequest) (authz.CapabilityLease, error) {
	if err := service.validateCaller(ctx, principal, request.TenantID, request.ProjectID); err != nil || request.LeaseID == "" || request.FencingToken < 1 {
		if err != nil {
			return authz.CapabilityLease{}, err
		}
		return authz.CapabilityLease{}, invalidRequest()
	}
	return service.manager.Heartbeat(ctx, authz.LeaseHeartbeatRequest{
		LeaseID: request.LeaseID, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: principal.ID, FencingToken: request.FencingToken,
	})
}

func (service *Service) Revoke(ctx context.Context, principal authn.Principal, request RevokeRequest) error {
	if err := service.validateCaller(ctx, principal, request.TenantID, request.ProjectID); err != nil {
		return err
	}
	if request.LeaseID == "" || !validIdempotencyKey(request.IdempotencyKey) {
		return invalidRequest()
	}
	digest, err := revokeRequestDigest(principal, request)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeInvalidArgument, "", err, map[string]any{"scope": "lease revoke idempotency"})
	}
	return service.manager.Revoke(ctx, authz.LeaseRevokeRequest{
		LeaseID: request.LeaseID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		Actor: principal, Reason: request.Reason, RequestDigest: digest,
	})
}

func (service *Service) authorizeGrant(ctx context.Context, principal authn.Principal, request GrantRequest) (authz.PolicyInput, authz.PolicyDecision, error) {
	if service == nil || service.manager == nil || service.policy == nil || service.scopes == nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := service.validateCaller(ctx, principal, request.TenantID, request.ProjectID); err != nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, err
	}
	if (request.TaskID == "" && authz.LeaseRoleRequiresTask(principal.Role)) || request.Action == "" || request.ParameterDigest == "" || request.BudgetAccountID == "" || request.TTL < 0 || !validIdempotencyKey(request.IdempotencyKey) {
		return authz.PolicyInput{}, authz.PolicyDecision{}, invalidRequest()
	}
	scope, err := service.scopes.Resolve(ctx, ScopeQuery{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		BudgetAccountID: request.BudgetAccountID, ApprovalID: request.ApprovalID,
		PrincipalID: principal.ID, Role: principal.Role, Action: request.Action,
	})
	if err != nil {
		return authz.PolicyInput{}, authz.PolicyDecision{}, aorerrors.Wrap(aorerrors.CodePolicyDenied, "", err, map[string]any{"scope": "lease authority"})
	}
	if scope.Project.TenantID != request.TenantID || scope.Project.ID != request.ProjectID || !leaseTaskScopeMatches(scope.Task, request.TenantID, request.ProjectID, request.TaskID) || scope.Budget.AccountID != request.BudgetAccountID || !scope.Budget.Available {
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

func leaseTaskScopeMatches(task authz.TaskScope, tenantID, projectID, taskID string) bool {
	if taskID == "" {
		return task.ID == "" && task.TenantID == "" && task.ProjectID == "" && task.State == "" && task.StateVersion == 0 && task.SpecDigest == ""
	}
	return task.TenantID == tenantID && task.ProjectID == projectID && task.ID == taskID
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

func grantRequestDigest(principal authn.Principal, input authz.PolicyInput, grant authz.PolicyDecision, request GrantRequest) (string, error) {
	var notAfter *time.Time
	if !request.NotAfter.IsZero() {
		value := request.NotAfter.UTC()
		notAfter = &value
	}
	encoded, err := json.Marshal(struct {
		Principal       authn.Principal    `json:"principal"`
		Project         authz.ProjectScope `json:"project"`
		Task            authz.TaskScope    `json:"task"`
		Action          string             `json:"action"`
		Resource        authz.Resource     `json:"resource"`
		ParameterDigest string             `json:"parameterDigest"`
		Budget          authz.BudgetScope  `json:"budget"`
		ApprovalID      string             `json:"approvalId,omitempty"`
		IdempotencyKey  string             `json:"idempotencyKey"`
		PolicyVersion   string             `json:"policyVersion"`
		Constraints     authz.Constraints  `json:"constraints"`
		TTLNanoseconds  int64              `json:"ttlNanoseconds"`
		NotAfter        *time.Time         `json:"notAfter,omitempty"`
	}{
		Principal: principal, Project: input.Project, Task: input.Task,
		Action: input.Action, Resource: input.Resource, ParameterDigest: input.ParameterDigest,
		Budget: input.Budget, ApprovalID: request.ApprovalID, IdempotencyKey: request.IdempotencyKey, PolicyVersion: grant.PolicyVersion,
		Constraints: grant.Constraints, TTLNanoseconds: int64(request.TTL), NotAfter: notAfter,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func revokeRequestDigest(principal authn.Principal, request RevokeRequest) (string, error) {
	encoded, err := json.Marshal(struct {
		Principal      authn.Principal `json:"principal"`
		TenantID       string          `json:"tenantId"`
		ProjectID      string          `json:"projectId"`
		TaskID         string          `json:"taskId"`
		LeaseID        string          `json:"leaseId"`
		Reason         string          `json:"reason"`
		IdempotencyKey string          `json:"idempotencyKey"`
	}{
		Principal: principal, TenantID: request.TenantID, ProjectID: request.ProjectID,
		TaskID: request.TaskID, LeaseID: request.LeaseID, Reason: request.Reason,
		IdempotencyKey: request.IdempotencyKey,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func validIdempotencyKey(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
