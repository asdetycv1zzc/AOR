//go:build postgres_integration

package authz

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresLeaseStoreLifecycle(t *testing.T) {
	databaseURL := os.Getenv("AOR_TEST_DATABASE_DSN")
	if databaseURL == "" {
		t.Fatal("AOR_TEST_DATABASE_DSN is required with the postgres_integration build tag")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewPostgresLeaseStore(database)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	manager, err := NewLeaseManager(LeaseManagerConfig{Store: store, Signer: signer, Clock: func() time.Time { return now }, DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute, HeartbeatInterval: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "a1000000-0000-4000-8000-000000000001"
	const projectID = "a2000000-0000-4000-8000-000000000001"
	const taskID = "a6000000-0000-4000-8000-000000000001"
	const agentID = "agent_integration_lease"
	principal := authn.Principal{ID: agentID, Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: tenantID, ProjectID: projectID}
	binding := DecisionBinding{PrincipalID: agentID, TenantID: tenantID, ProjectID: projectID, ProjectVersion: 7, TaskID: taskID, TaskVersion: 9, SpecDigest: testSpecDigest, Role: authn.RoleExecutor, Action: ActionToolInvoke, Resource: Resource{Type: "tool", ID: "tool://repository/repo.read@1.0.0"}, ParameterDigest: testParamsDigest, BudgetAccountID: projectID}
	grant := PolicyDecision{Decision: DecisionAllow, PolicyVersion: testPolicyVersion, Constraints: Constraints{ExpiresAt: now.Add(10 * time.Minute)}, ReasonCodes: []string{"LEASE_APPROVED"}, RuleID: "integration.tool", Binding: &binding}
	lease, err := manager.Issue(context.Background(), LeaseRequest{ID: "lease_integration_postgres", AgentInstanceID: agentID, Principal: principal, TenantID: tenantID, ProjectID: projectID, ProjectVersion: 7, TaskID: taskID, TaskVersion: 9, SpecDigest: testSpecDigest, Role: authn.RoleExecutor, Action: ActionToolInvoke, Resource: binding.Resource, ParameterDigest: testParamsDigest, Capabilities: []string{ActionToolInvoke}, PolicyVersion: testPolicyVersion, BudgetAccountID: projectID, Grant: grant, RequestDigest: testParamsDigest})
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.Get(withLeaseTenant(context.Background(), tenantID), lease.ID)
	if err != nil || !found || loaded.Signature != lease.Signature {
		t.Fatalf("load lease: found=%v lease=%#v err=%v", found, loaded, err)
	}
	if _, found, err := store.Get(withLeaseTenant(context.Background(), "b1000000-0000-4000-8000-000000000001"), lease.ID); err != nil || found {
		t.Fatalf("cross-tenant lookup: found=%v err=%v", found, err)
	}
	now = now.Add(time.Minute)
	renewed, err := manager.Renew(context.Background(), LeaseRenewalRequest{LeaseID: lease.ID, TenantID: tenantID, FencingToken: lease.FencingToken, PrincipalID: lease.PrincipalID, PrincipalType: lease.PrincipalType, Role: lease.Role, PolicyVersion: lease.PolicyVersion, Grant: grant, RequestDigest: testSpecDigest})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.FencingToken != 2 {
		t.Fatalf("renewed fencing token = %d", renewed.FencingToken)
	}
	loaded, found, err = store.Get(withLeaseTenant(context.Background(), tenantID), lease.ID)
	if err != nil || !found || loaded.Nonce != testSpecDigest || loaded.Signature != renewed.Signature {
		t.Fatalf("load renewed lease: found=%v lease=%#v err=%v", found, loaded, err)
	}
	if err := manager.Revoke(context.Background(), LeaseRevokeRequest{LeaseID: lease.ID, ProjectID: projectID, TaskID: taskID, Actor: principal, Reason: "integration test", RequestDigest: testParamsDigest}); err != nil {
		t.Fatal(err)
	}
	loaded, found, err = store.Get(withLeaseTenant(context.Background(), tenantID), lease.ID)
	if err != nil || !found || loaded.State != LeaseRevoked || loaded.Nonce != testParamsDigest || loaded.FencingToken != 3 {
		t.Fatalf("load revoked lease: found=%v lease=%#v err=%v", found, loaded, err)
	}
	var fencingToken int64
	if err := database.QueryRowContext(withLeaseTenant(context.Background(), tenantID), `SELECT latest_fencing_token FROM module_tasks WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, taskID).Scan(&fencingToken); err == nil {
		t.Fatal("direct connection unexpectedly bypassed tenant transaction boundary")
	}
}
