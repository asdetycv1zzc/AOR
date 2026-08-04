package toolbroker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type capturedAuthzPolicy struct {
	input authz.PolicyInput
	err   error
}

func (policy *capturedAuthzPolicy) Evaluate(_ context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	policy.input = input
	if policy.err != nil {
		return authz.PolicyDecision{}, policy.err
	}
	return authz.PolicyDecision{Decision: authz.DecisionAllow, PolicyVersion: "policy-1", ReasonCodes: []string{"LEASE_VALID"}}, nil
}

type fixedToolScopes struct {
	scope ToolAuthorizationScope
	query *ToolAuthorizationScopeQuery
}

func (resolver fixedToolScopes) ResolveToolAuthorizationScope(_ context.Context, query ToolAuthorizationScopeQuery) (ToolAuthorizationScope, error) {
	if resolver.query != nil {
		*resolver.query = query
	}
	return resolver.scope, nil
}

func TestOPAPolicyEvaluatorUsesAuthoritativeCompleteScope(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := &capturedAuthzPolicy{}
	scope := ToolAuthorizationScope{
		Project: authz.ProjectScope{TenantID: "tenant-1", ID: "project-1", State: "EXECUTING", StateVersion: 4, Classification: "INTERNAL"},
		Task:    authz.TaskScope{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", State: "EXECUTING", StateVersion: 7, SpecDigest: testSHA256("spec"), OwnedPaths: []string{"src/**"}, ExecutionPlatform: "LINUX", SandboxLevel: "CONTAINER", WorkloadTrust: "UNTRUSTED", DeploymentProfile: "PRODUCTION"},
		Budget:  authz.BudgetScope{AccountID: "budget-1", Available: true},
	}
	var scopeQuery ToolAuthorizationScopeQuery
	evaluator := OPAPolicyEvaluator{Policy: policy, Scopes: fixedToolScopes{scope: scope, query: &scopeQuery}, Clock: func() time.Time { return now }}
	request := request()
	request.TenantID = "tenant-1"
	request.ProjectID = "project-1"
	request.TaskID = "task-1"
	request.Principal = Principal{ID: "agent-1", Type: string(authn.PrincipalAgentInstance), Role: authn.RoleExecutor}
	request.Lease.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	decision, err := evaluator.Evaluate(context.Background(), descriptor(), request)
	if err != nil || !decision.Allow {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	digest, _ := canonicaljson.Digest(request.Parameters)
	if policy.input.Project.StateVersion != 4 || policy.input.Task.StateVersion != 7 || policy.input.ParameterDigest != digest || policy.input.Resource.ID != "tool://repo/repo.read@1.0.0" || policy.input.Principal.TenantID != "tenant-1" || policy.input.Lease == nil || policy.input.Lease.FencingToken != 1 {
		t.Fatalf("OPA input was not exact: %#v", policy.input)
	}
	if scopeQuery.Action != authz.ActionToolInvoke {
		t.Fatalf("scope action = %q", scopeQuery.Action)
	}
}

func TestOPAPolicyEvaluatorFailsClosedForScopeAndPolicyFailures(t *testing.T) {
	request := request()
	request.TenantID = "tenant-1"
	request.ProjectID = "project-1"
	request.TaskID = "task-1"
	request.Principal = Principal{ID: "agent-1", Type: string(authn.PrincipalAgentInstance), Role: authn.RoleExecutor}
	scope := ToolAuthorizationScope{Project: authz.ProjectScope{TenantID: "other", ID: "project-1"}, Task: authz.TaskScope{TenantID: "other", ProjectID: "project-1", ID: "task-1"}, Budget: authz.BudgetScope{AccountID: "budget-1", Available: true}}
	evaluator := OPAPolicyEvaluator{Policy: &capturedAuthzPolicy{}, Scopes: fixedToolScopes{scope: scope}}
	if _, err := evaluator.Evaluate(context.Background(), descriptor(), request); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("scope error = %v", err)
	}
	evaluator = OPAPolicyEvaluator{Policy: &capturedAuthzPolicy{err: errors.New("OPA unavailable")}, Scopes: fixedToolScopes{scope: ToolAuthorizationScope{Project: authz.ProjectScope{TenantID: "tenant-1", ID: "project-1"}, Task: authz.TaskScope{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1"}, Budget: authz.BudgetScope{AccountID: "budget-1", Available: true}}}}
	if _, err := evaluator.Evaluate(context.Background(), descriptor(), request); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("OPA error = %v", err)
	}
}
