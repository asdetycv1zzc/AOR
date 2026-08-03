package authz

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const (
	testPolicyVersion = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testSpecDigest    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testParamsDigest  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

var authzTestNow = time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)

type approvalVerifierFunc func(context.Context, Approval) error

func (f approvalVerifierFunc) Verify(ctx context.Context, approval Approval) error {
	return f(ctx, approval)
}

func testPrincipal() authn.Principal {
	return authn.Principal{ID: "agent_1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant_1", ProjectID: "project_1"}
}

func testInput() PolicyInput {
	return PolicyInput{
		Principal:       testPrincipal(),
		Project:         ProjectScope{TenantID: "tenant_1", ID: "project_1", State: "EXECUTING", StateVersion: 7, Classification: "INTERNAL"},
		Task:            TaskScope{TenantID: "tenant_1", ProjectID: "project_1", ID: "task_1", State: "EXECUTING", StateVersion: 9, SpecDigest: testSpecDigest, OwnedPaths: []string{"internal/auth/**"}},
		Action:          ActionRepoWrite,
		Resource:        Resource{Type: "repository_path", Path: "internal/auth/token.go"},
		ParameterDigest: testParamsDigest,
		Budget:          BudgetScope{AccountID: "budget_1", Available: true},
		Context:         ExecutionContext{Platform: "LINUX", SandboxLevel: "CONTAINER"},
	}
}

func testManager(t *testing.T, clock func() time.Time) (*LeaseManager, *MemoryLeaseStore) {
	t.Helper()
	signer, err := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryLeaseStore()
	manager, err := NewLeaseManager(LeaseManagerConfig{Store: store, Signer: signer, Clock: clock, DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute, HeartbeatInterval: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return manager, store
}

func testEngine(manager *LeaseManager, clock func() time.Time) *Engine {
	return NewEngine(EngineConfig{Bundle: PolicyBundle{Version: testPolicyVersion, Digest: testPolicyVersion, Available: true}, LeaseManager: manager, ApprovalVerifier: approvalVerifierFunc(func(context.Context, Approval) error { return nil }), Clock: clock})
}

func issueForInput(t *testing.T, manager *LeaseManager, engine *Engine, input PolicyInput, now time.Time) (CapabilityLease, PolicyInput) {
	t.Helper()
	grantInput := input
	grantInput.Lease = nil
	grant, err := engine.EvaluateLeaseGrant(context.Background(), grantInput)
	if err != nil || grant.Decision != DecisionAllow {
		t.Fatalf("grant denied: decision=%#v err=%v", grant, err)
	}
	lease, err := manager.Issue(context.Background(), LeaseRequest{
		Principal: input.Principal, TenantID: input.Project.TenantID, ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion,
		TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role,
		Action: input.Action, Resource: input.Resource, ParameterDigest: input.ParameterDigest, Capabilities: []string{input.Action},
		PolicyVersion: testPolicyVersion, BudgetAccountID: input.Budget.AccountID, Grant: grant, Now: now,
	})
	if err != nil {
		t.Fatalf("issue lease: %v", err)
	}
	input.Lease = leaseReferencePointer(lease)
	return lease, input
}

func leaseReferencePointer(lease CapabilityLease) *LeaseReference {
	reference := lease.Reference()
	return &reference
}

func TestCapabilityLeaseLifecycleAndFencing(t *testing.T) {
	now := authzTestNow
	clock := func() time.Time { return now }
	manager, _ := testManager(t, clock)
	engine := testEngine(manager, clock)
	lease, input := issueForInput(t, manager, engine, testInput(), now)

	decision, err := engine.Authorize(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow || decision.Constraints.PathGlob != "internal/auth/**" || decision.Constraints.ExpiresAt != lease.ExpiresAt {
		t.Fatalf("authorized write rejected: decision=%#v err=%v", decision, err)
	}

	now = now.Add(10 * time.Second)
	if _, err := manager.Heartbeat(context.Background(), LeaseHeartbeatRequest{LeaseID: lease.ID, PrincipalID: lease.PrincipalID, FencingToken: lease.FencingToken, Now: now}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	grantInput := testInput()
	grant, err := engine.EvaluateLeaseGrant(context.Background(), grantInput)
	if err != nil {
		t.Fatalf("renewal policy grant: %v", err)
	}
	renewed, err := manager.Renew(context.Background(), LeaseRenewalRequest{LeaseID: lease.ID, FencingToken: lease.FencingToken, PrincipalID: lease.PrincipalID, PrincipalType: lease.PrincipalType, Role: lease.Role, PolicyVersion: lease.PolicyVersion, Grant: grant, Now: now})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.FencingToken != lease.FencingToken+1 {
		t.Fatalf("fencing token did not advance: old=%d new=%d", lease.FencingToken, renewed.FencingToken)
	}

	oldInput := input
	oldInput.Lease = leaseReferencePointer(lease)
	decision, err = engine.Authorize(context.Background(), oldInput)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("old fenced lease accepted: decision=%#v err=%v", decision, err)
	}

	renewedInput := testInput()
	renewedInput.Lease = leaseReferencePointer(renewed)
	decision, err = engine.Authorize(context.Background(), renewedInput)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("renewed lease rejected: decision=%#v err=%v", decision, err)
	}
	if err := manager.Revoke(context.Background(), LeaseRevokeRequest{LeaseID: renewed.ID, Actor: testPrincipal(), Reason: "task canceled", Now: now}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	decision, err = engine.Authorize(context.Background(), renewedInput)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("revoked lease accepted: decision=%#v err=%v", decision, err)
	}
	assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
}

func TestLeaseRejectsDenyAndReboundGrant(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	input := testInput()
	base := LeaseRequest{Principal: input.Principal, TenantID: input.Project.TenantID, ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion, TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role, Action: input.Action, Resource: input.Resource, ParameterDigest: input.ParameterDigest, Capabilities: []string{input.Action}, PolicyVersion: testPolicyVersion, BudgetAccountID: input.Budget.AccountID, Now: authzTestNow}
	base.Grant = denyDecision(testPolicyVersion, "DEFAULT_DENY")
	if _, err := manager.Issue(context.Background(), base); err == nil {
		t.Fatal("deny decision issued a lease")
	}

	engine := testEngine(manager, func() time.Time { return authzTestNow })
	grant, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	base.Grant = grant
	base.Resource.Path = "internal/state/project.go"
	if _, err := manager.Issue(context.Background(), base); err == nil {
		t.Fatal("grant was rebound to another resource")
	}
}

func TestLeaseSignatureTamperingFailsClosed(t *testing.T) {
	manager, store := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	lease, _ := issueForInput(t, manager, engine, testInput(), authzTestNow)
	tampered := lease
	tampered.ParameterDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ok, err := store.CompareAndSwap(context.Background(), lease.ID, lease.FencingToken, tampered)
	if err != nil || !ok {
		t.Fatalf("install tampered fixture: ok=%v err=%v", ok, err)
	}
	_, err = manager.ValidateActive(context.Background(), lease.ID, authzTestNow)
	assertAuthzErrorCode(t, err, aorerrors.CodeUnauthorized)
}

func TestLeaseExpiresAfterMissedHeartbeats(t *testing.T) {
	now := authzTestNow
	manager, _ := testManager(t, func() time.Time { return now })
	engine := testEngine(manager, func() time.Time { return now })
	lease, _ := issueForInput(t, manager, engine, testInput(), now)
	now = now.Add(3 * time.Duration(lease.HeartbeatIntervalSeconds) * time.Second)
	_, err := manager.ValidateActive(context.Background(), lease.ID, now)
	assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
}

func TestConcurrentRenewalHasOneFencingWinner(t *testing.T) {
	now := authzTestNow
	manager, _ := testManager(t, func() time.Time { return now })
	engine := testEngine(manager, func() time.Time { return now })
	lease, _ := issueForInput(t, manager, engine, testInput(), now)
	grant, err := engine.EvaluateLeaseGrant(context.Background(), testInput())
	if err != nil {
		t.Fatal(err)
	}
	request := LeaseRenewalRequest{LeaseID: lease.ID, FencingToken: lease.FencingToken, PrincipalID: lease.PrincipalID, PrincipalType: lease.PrincipalType, Role: lease.Role, PolicyVersion: lease.PolicyVersion, Grant: grant, Now: now.Add(time.Second)}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, renewErr := manager.Renew(context.Background(), request)
			results <- renewErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for result := range results {
		if result == nil {
			successes++
			continue
		}
		var typed *aorerrors.Error
		if errors.As(result, &typed) && typed.Code == aorerrors.CodeConflict {
			conflicts++
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("expected one renewal and one fencing conflict, got successes=%d conflicts=%d", successes, conflicts)
	}
}

func assertAuthzErrorCode(t *testing.T, err error, expected aorerrors.Code) {
	t.Helper()
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != expected {
		t.Fatalf("expected %s, got %v", expected, err)
	}
}
