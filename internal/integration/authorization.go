package integration

import (
	"context"
	"encoding/json"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type leaseValidator interface {
	Validate(context.Context, authz.LeaseCheck) (authz.CapabilityLease, error)
}

type authorizationProjectSource interface {
	Project(context.Context, string, string) (state.Project, bool, error)
}

type LeaseAuthorizer struct {
	leases   leaseValidator
	policy   authz.PolicyEvaluator
	projects authorizationProjectSource
	clock    func() time.Time
}

func NewLeaseAuthorizer(leases leaseValidator, policy authz.PolicyEvaluator, projects authorizationProjectSource, clock func() time.Time) (*LeaseAuthorizer, error) {
	if leases == nil || policy == nil || projects == nil {
		return nil, ErrWorkflowUnavailable
	}
	if clock == nil {
		clock = time.Now
	}
	return &LeaseAuthorizer{leases: leases, policy: policy, projects: projects, clock: clock}, nil
}

func (authorizer *LeaseAuthorizer) Authorize(ctx context.Context, request AuthorizationRequest) (string, error) {
	if authorizer == nil || authorizer.leases == nil || authorizer.policy == nil || authorizer.projects == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrNotAudited
	}
	project, found, err := authorizer.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil || !found || project.TenantID != request.TenantID || project.ID != request.ProjectID || project.State != contracts.ProjectIntegrating || project.Version != request.ExpectedVersion {
		return "", ErrNotAudited
	}
	parameterDigest, err := AuthorizationParameterDigest(request)
	if err != nil {
		return "", ErrNotAudited
	}
	resource := IntegrationResource(request.IntegrationID)
	lease, err := authorizer.leases.Validate(ctx, authz.LeaseCheck{
		LeaseID: request.LeaseID, AgentInstanceID: request.PrincipalID, PrincipalID: request.PrincipalID,
		PrincipalType: authn.PrincipalService, TenantID: request.TenantID, ProjectID: request.ProjectID,
		ProjectVersion: request.ExpectedVersion, Role: authn.RoleService, Action: authz.ActionIntegrationMerge,
		Resource: resource, ParameterDigest: parameterDigest, PolicyVersion: request.PolicyDigest,
		BudgetAccountID: request.ProjectID, Capability: authz.ActionIntegrationMerge,
		FencingToken: request.FencingToken, At: authorizer.clock().UTC(),
	})
	if err != nil {
		return "", ErrNotAudited
	}
	principal := authn.Principal{
		ID: request.PrincipalID, Type: authn.PrincipalService, Role: authn.RoleService,
		TenantID: request.TenantID, ProjectID: request.ProjectID,
	}
	input := authz.PolicyInput{
		Principal: principal,
		Project: authz.ProjectScope{
			TenantID: project.TenantID, ID: project.ID, State: string(project.State),
			StateVersion: project.Version, Classification: integrationClassification(project.DataClassification),
		},
		Action: authz.ActionIntegrationMerge, Resource: resource, ParameterDigest: parameterDigest,
		Budget: authz.BudgetScope{AccountID: request.ProjectID, Available: true},
		Lease: &authz.LeaseReference{
			ID: lease.ID, ExpiresAt: lease.ExpiresAt, PolicyVersion: lease.PolicyVersion,
			FencingToken: lease.FencingToken,
		},
	}
	decision, err := authorizer.policy.Evaluate(ctx, input)
	if err != nil || !decision.Decision.Allowed() || decision.PolicyVersion != request.PolicyDigest {
		return "", ErrNotAudited
	}
	encoded, err := json.Marshal(struct {
		RequestSHA256 string         `json:"requestSha256"`
		PolicyVersion string         `json:"policyVersion"`
		RuleID        string         `json:"ruleId"`
		Decision      authz.Decision `json:"decision"`
	}{parameterDigest, decision.PolicyVersion, decision.RuleID, decision.Decision})
	if err != nil {
		return "", ErrNotAudited
	}
	return canonicaljson.Digest(encoded)
}

func AuthorizationParameterDigest(request AuthorizationRequest) (string, error) {
	candidates := canonicalCandidates(request.Candidates)
	if request.TenantID == "" || request.ProjectID == "" || !safeIntegrationID(request.IntegrationID) || request.PrincipalID == "" || !commitID(request.BaseCommit) || len(candidates) == 0 || !digestPattern(request.PolicyDigest) || request.ExpectedVersion < 1 || !validAttemptBinding(request.OwnerTaskID, request.Attempt) {
		return "", ErrInvalidRequest
	}
	for _, candidate := range candidates {
		if candidate.TaskID == "" || candidate.ModuleID == "" || !commitID(candidate.SubmissionCommit) || candidate.ModuleSpecRef.Validate() != nil || !digestPattern(candidate.EvidenceSHA256) || !candidate.AuditPassed {
			return "", ErrInvalidRequest
		}
	}
	encoded, err := json.Marshal(struct {
		TenantID        string      `json:"tenantId"`
		ProjectID       string      `json:"projectId"`
		IntegrationID   string      `json:"integrationId"`
		PrincipalID     string      `json:"principalId"`
		PolicyDigest    string      `json:"policyDigest"`
		ExpectedVersion int64       `json:"expectedVersion"`
		BaseCommit      string      `json:"baseCommit"`
		Candidates      []Candidate `json:"candidates"`
		OwnerTaskID     string      `json:"ownerTaskId,omitempty"`
		Attempt         int         `json:"attempt"`
	}{request.TenantID, request.ProjectID, request.IntegrationID, request.PrincipalID, request.PolicyDigest, request.ExpectedVersion, request.BaseCommit, candidates, request.OwnerTaskID, request.Attempt})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func IntegrationResource(integrationID string) authz.Resource {
	return authz.Resource{Type: "integration", ID: integrationID}
}

var _ IntegrationAuthorizer = (*LeaseAuthorizer)(nil)
