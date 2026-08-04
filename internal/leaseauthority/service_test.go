package leaseauthority

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const leasePolicyVersion = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var leaseTestNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

type fixedScopeResolver struct {
	scope Scope
	err   error
	query ScopeQuery
}

func (resolver *fixedScopeResolver) Resolve(_ context.Context, query ScopeQuery) (Scope, error) {
	resolver.query = query
	return resolver.scope, resolver.err
}

type bindingGrantEvaluator struct {
	input authz.PolicyInput
	err   error
	deny  bool
}

func (evaluator *bindingGrantEvaluator) EvaluateLeaseGrant(_ context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	evaluator.input = input
	if evaluator.err != nil {
		return authz.PolicyDecision{}, evaluator.err
	}
	if evaluator.deny {
		return authz.PolicyDecision{Decision: authz.DecisionDeny, PolicyVersion: leasePolicyVersion, ReasonCodes: []string{"DENIED"}, RuleID: "aor.test.deny"}, nil
	}
	binding := authz.DecisionBinding{
		PrincipalID: input.Principal.ID, TenantID: input.Project.TenantID,
		ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion,
		TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion,
		SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role,
		Action: input.Action, Resource: input.Resource,
		ParameterDigest: input.ParameterDigest, BudgetAccountID: input.Budget.AccountID,
	}
	return authz.PolicyDecision{
		Decision: authz.DecisionAllow, PolicyVersion: leasePolicyVersion,
		ReasonCodes: []string{"ALLOWED"}, RuleID: "aor.test.allow", Binding: &binding,
	}, nil
}

func TestServiceIssuesExactlyBoundLeaseFromAuthoritativeScope(t *testing.T) {
	service, scopes, policy, principal := testService(t)
	request := testGrantRequest()
	ctx := principalContext(t, principal)

	lease, err := service.Issue(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}
	if lease.State != authz.LeaseActive || lease.PrincipalID != principal.ID || lease.AgentInstanceID != principal.ID || lease.ProjectVersion != 7 || lease.TaskVersion != 9 || lease.SpecDigest != testScope().Task.SpecDigest || lease.Action != request.Action || lease.ParameterDigest != request.ParameterDigest || lease.BudgetAccountID != request.BudgetAccountID || lease.PolicyVersion != leasePolicyVersion || lease.FencingToken != 1 || !reflect.DeepEqual(lease.Capabilities, []string{request.Action}) {
		t.Fatalf("lease = %#v", lease)
	}
	if scopes.query.PrincipalID != principal.ID || scopes.query.Role != principal.Role || scopes.query.ApprovalID != request.ApprovalID {
		t.Fatalf("scope query = %#v", scopes.query)
	}
	if policy.input.Project.StateVersion != 7 || policy.input.Task.StateVersion != 9 || policy.input.Context.Platform != "LINUX" || policy.input.Context.SandboxLevel != "CONTAINER" {
		t.Fatalf("policy input = %#v", policy.input)
	}
	replayed, err := service.Issue(ctx, principal, request)
	if err != nil || replayed.ID != lease.ID || replayed.Signature != lease.Signature {
		t.Fatalf("idempotent issue = %#v, err=%v", replayed, err)
	}
	changed := request
	changed.ParameterDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	if _, err := service.Issue(ctx, principal, changed); errorCode(err) != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed idempotent issue error = %v", err)
	}
}

func TestServiceRenewalAdvancesFencingAndRejectsChangedScope(t *testing.T) {
	service, scopes, _, principal := testService(t)
	ctx := principalContext(t, principal)
	request := testGrantRequest()
	lease, err := service.Issue(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}

	renewed, err := service.Renew(ctx, principal, RenewRequest{
		GrantRequest: request, LeaseID: lease.ID,
		FencingToken: lease.FencingToken, PolicyVersion: lease.PolicyVersion,
	})
	if err != nil || renewed.FencingToken != lease.FencingToken+1 {
		t.Fatalf("renewed = %#v, err=%v", renewed, err)
	}
	replayed, err := service.Renew(ctx, principal, RenewRequest{
		GrantRequest: request, LeaseID: lease.ID,
		FencingToken: lease.FencingToken, PolicyVersion: lease.PolicyVersion,
	})
	if err != nil || replayed.FencingToken != renewed.FencingToken || replayed.Signature != renewed.Signature {
		t.Fatalf("idempotent renewal = %#v, err=%v", replayed, err)
	}
	differentRenewal := request
	differentRenewal.IdempotencyKey = "renew-different"
	if _, err := service.Renew(ctx, principal, RenewRequest{
		GrantRequest: differentRenewal, LeaseID: lease.ID,
		FencingToken: lease.FencingToken, PolicyVersion: lease.PolicyVersion,
	}); err == nil {
		t.Fatal("stale fencing token with different idempotency key renewed")
	}

	scopes.scope.Task.StateVersion++
	request.IdempotencyKey = "renew-changed-scope"
	if _, err := service.Renew(ctx, principal, RenewRequest{
		GrantRequest: request, LeaseID: lease.ID,
		FencingToken: renewed.FencingToken, PolicyVersion: renewed.PolicyVersion,
	}); err == nil {
		t.Fatal("changed task version renewed existing lease")
	}
}

func TestServiceHeartbeatAndRevocationUseAuthenticatedPrincipal(t *testing.T) {
	service, _, _, principal := testService(t)
	ctx := principalContext(t, principal)
	lease, err := service.Issue(ctx, principal, testGrantRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Heartbeat(ctx, principal, HeartbeatRequest{TenantID: principal.TenantID, ProjectID: principal.ProjectID, TaskID: "task_other", LeaseID: lease.ID, FencingToken: lease.FencingToken}); errorCode(err) != aorerrors.CodeForbidden {
		t.Fatalf("cross-task heartbeat error = %v", err)
	}
	heartbeat, err := service.Heartbeat(ctx, principal, HeartbeatRequest{TenantID: principal.TenantID, ProjectID: principal.ProjectID, TaskID: lease.TaskID, LeaseID: lease.ID, FencingToken: lease.FencingToken})
	if err != nil || heartbeat.ID != lease.ID {
		t.Fatalf("heartbeat = %#v, err=%v", heartbeat, err)
	}
	revoke := RevokeRequest{TenantID: principal.TenantID, ProjectID: principal.ProjectID, TaskID: lease.TaskID, LeaseID: lease.ID, Reason: "task canceled", IdempotencyKey: "revoke-1"}
	wrongTask := revoke
	wrongTask.TaskID = "task_other"
	if err := service.Revoke(ctx, principal, wrongTask); errorCode(err) != aorerrors.CodeForbidden {
		t.Fatalf("cross-task revoke error = %v", err)
	}
	if err := service.Revoke(ctx, principal, revoke); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, principal, revoke); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	changed := revoke
	changed.Reason = "different reason"
	if err := service.Revoke(ctx, principal, changed); errorCode(err) != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed idempotent revoke error = %v", err)
	}
	if _, err := service.Heartbeat(ctx, principal, HeartbeatRequest{TenantID: principal.TenantID, ProjectID: principal.ProjectID, TaskID: lease.TaskID, LeaseID: lease.ID, FencingToken: lease.FencingToken + 1}); err == nil {
		t.Fatal("revoked lease accepted heartbeat")
	}
}

func TestServiceFailsClosedForCallerScopePolicyAndBudget(t *testing.T) {
	service, scopes, policy, principal := testService(t)
	request := testGrantRequest()
	ctx := principalContext(t, principal)

	other := principal
	other.ID = "agent_other"
	if _, err := service.Issue(ctx, other, request); errorCode(err) != aorerrors.CodeForbidden {
		t.Fatalf("mismatched caller error = %v", err)
	}
	request.TenantID = "tenant_other"
	if _, err := service.Issue(ctx, principal, request); errorCode(err) != aorerrors.CodeForbidden {
		t.Fatalf("cross-tenant error = %v", err)
	}

	request = testGrantRequest()
	scopes.scope.Budget.Available = false
	if _, err := service.Issue(ctx, principal, request); errorCode(err) != aorerrors.CodePolicyDenied {
		t.Fatalf("unavailable budget error = %v", err)
	}

	scopes.scope = testScope()
	policy.deny = true
	if _, err := service.Issue(ctx, principal, request); errorCode(err) != aorerrors.CodePolicyDenied {
		t.Fatalf("policy denial error = %v", err)
	}
}

func testService(t *testing.T) (*Service, *fixedScopeResolver, *bindingGrantEvaluator, authn.Principal) {
	t.Helper()
	signer, err := authz.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: authz.NewMemoryLeaseStore(), Signer: signer,
		Clock: func() time.Time { return leaseTestNow }, HeartbeatInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	scopes := &fixedScopeResolver{scope: testScope()}
	policy := &bindingGrantEvaluator{}
	service, err := New(Config{Manager: manager, Policy: policy, Scopes: scopes, Clock: func() time.Time { return leaseTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{ID: "agent_1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant_1", ProjectID: "project_1"}
	return service, scopes, policy, principal
}

func testScope() Scope {
	return Scope{
		Project: authz.ProjectScope{TenantID: "tenant_1", ID: "project_1", State: "EXECUTING", StateVersion: 7, Classification: "INTERNAL"},
		Task: authz.TaskScope{
			TenantID: "tenant_1", ProjectID: "project_1", ID: "task_1", State: "EXECUTING", StateVersion: 9,
			SpecDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			OwnedPaths: []string{"internal/auth/**"}, ExecutionPlatform: "LINUX", SandboxLevel: "CONTAINER",
			WorkloadTrust: "UNTRUSTED", DeploymentProfile: "PRODUCTION",
		},
		Budget: authz.BudgetScope{AccountID: "budget_1", Available: true},
	}
}

func testGrantRequest() GrantRequest {
	return GrantRequest{
		TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1",
		Action:          authz.ActionToolInvoke,
		Resource:        authz.Resource{Type: "tool", ID: "tool://repository/repo.read@1.0.0"},
		ParameterDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		BudgetAccountID: "budget_1", ApprovalID: "approval_1", IdempotencyKey: "lease-request-1",
	}
}

func principalContext(t *testing.T, principal authn.Principal) context.Context {
	t.Helper()
	ctx, err := authn.ContextWithPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func errorCode(err error) aorerrors.Code {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}
