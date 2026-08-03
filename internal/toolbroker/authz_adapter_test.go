package toolbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type staticExecutionScopes struct {
	scope ExecutionScope
}

func (resolver staticExecutionScopes) ResolveExecutionScope(context.Context, string, string, string) (ExecutionScope, error) {
	return resolver.scope, nil
}

func TestAuthzLeaseCheckerValidatesTrustedExactBinding(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	manager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Clock:             func() time.Time { return now },
		DefaultTTL:        2 * time.Minute,
		MaxTTL:            5 * time.Minute,
		HeartbeatInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new lease manager: %v", err)
	}
	parameters := []byte(`{"path":"README.md"}`)
	parameterDigest, err := canonicaljson.Digest(parameters)
	if err != nil {
		t.Fatalf("parameter digest: %v", err)
	}
	specDigest := testSHA256("module specification")
	resource := AuthorizationResource("repository", "repo.read", "1.0.0")
	binding := authz.DecisionBinding{
		PrincipalID: "agent-1", TenantID: "tenant-1", ProjectID: "project-1", ProjectVersion: 4,
		TaskID: "task-1", TaskVersion: 7, SpecDigest: specDigest, Role: authn.RoleExecutor,
		Action: authz.ActionToolInvoke, Resource: resource, ParameterDigest: parameterDigest, BudgetAccountID: "budget-1",
	}
	lease, err := manager.Issue(context.Background(), authz.LeaseRequest{
		ID: "lease-tool-1", Principal: authn.Principal{ID: "agent-1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant-1", ProjectID: "project-1"},
		TenantID: "tenant-1", ProjectID: "project-1", ProjectVersion: 4, TaskID: "task-1", TaskVersion: 7,
		SpecDigest: specDigest, Role: authn.RoleExecutor, Action: authz.ActionToolInvoke, Resource: resource,
		ParameterDigest: parameterDigest, Capabilities: []string{authz.ActionToolInvoke}, PolicyVersion: "policy-1", BudgetAccountID: "budget-1",
		Grant: authz.PolicyDecision{Decision: authz.DecisionAllow, PolicyVersion: "policy-1", Constraints: authz.Constraints{ExpiresAt: now.Add(10 * time.Minute)}, ReasonCodes: []string{"LEASE_APPROVED"}, RuleID: "test.tool", Binding: &binding},
	})
	if err != nil {
		t.Fatalf("issue exact lease: %v", err)
	}
	checker := AuthzLeaseChecker{Manager: manager, Scopes: staticExecutionScopes{scope: ExecutionScope{ProjectVersion: 4, TaskVersion: 7, SpecDigest: specDigest}}}
	validation := LeaseValidation{
		Lease:     Lease{ID: lease.ID, ExpiresAt: lease.ExpiresAt.Format(time.RFC3339Nano), FencingToken: lease.FencingToken},
		Principal: Principal{ID: "agent-1", Type: string(authn.PrincipalAgentInstance), Role: authn.RoleExecutor},
		TenantID:  "tenant-1", ProjectID: "project-1", TaskID: "task-1", ToolID: "repo.read", ToolVersion: "1.0.0", MCPServerID: "repository",
		Action: authz.ActionToolInvoke, Resource: authorizationResourceID("repository", "repo.read", "1.0.0"), ParameterSHA256: parameterDigest,
		PolicyVersion: "policy-1", BudgetAccountID: "budget-1", At: now,
	}
	if err := checker.Validate(context.Background(), validation); err != nil {
		t.Fatalf("validate exact lease: %v", err)
	}

	replayed := validation
	replayed.ParameterSHA256 = testSHA256("different parameters")
	if err := checker.Validate(context.Background(), replayed); err == nil {
		t.Fatal("parameter replay was accepted")
	}

	staleScope := checker
	staleScope.Scopes = staticExecutionScopes{scope: ExecutionScope{ProjectVersion: 4, TaskVersion: 8, SpecDigest: specDigest}}
	if err := staleScope.Validate(context.Background(), validation); err == nil {
		t.Fatal("stale task projection was accepted")
	}

	tamperedReference := validation
	tamperedReference.Lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute).Format(time.RFC3339Nano)
	if err := checker.Validate(context.Background(), tamperedReference); err == nil {
		t.Fatal("tampered lease reference was accepted")
	}
}

func testSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
