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
		Task:            TaskScope{TenantID: "tenant_1", ProjectID: "project_1", ID: "task_1", State: "EXECUTING", StateVersion: 9, SpecDigest: testSpecDigest, OwnedPaths: []string{"internal/auth/**"}, ExecutionPlatform: "LINUX", SandboxLevel: "CONTAINER", WorkloadTrust: "TRUSTED", DeploymentProfile: "PRODUCTION"},
		Action:          ActionRepoWrite,
		Resource:        Resource{Type: "repository_path", Path: "internal/auth/token.go"},
		ParameterDigest: testParamsDigest,
		Budget:          BudgetScope{AccountID: "budget_1", Available: true},
		Context:         ExecutionContext{Platform: "LINUX", SandboxLevel: "CONTAINER"},
	}
}

func knowledgeCuratorInput() PolicyInput {
	input := testInput()
	input.Principal = authn.Principal{ID: "curator_1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator, TenantID: "tenant_1", ProjectID: "project_1"}
	input.Task = TaskScope{}
	input.Action = ActionKnowledgeWrite
	input.Resource = Resource{Type: "knowledge.write", Path: "knowledge/global/rules.md"}
	input.Context = ExecutionContext{}
	input.Approval = &Approval{ID: "approval_1", TenantID: input.Project.TenantID, ProjectID: input.Project.ID, PrincipalID: "user_1", SubjectType: ActionKnowledgeWrite, SubjectID: input.Resource.Path, SubjectVersion: input.Project.StateVersion, SubjectDigest: input.ParameterDigest, IssuedAt: authzTestNow.Add(-time.Minute), ExpiresAt: authzTestNow.Add(time.Minute), Signature: "signed-approval"}
	return input
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
	request := leaseRequestForInput(input, grant)
	request.Now = now
	lease, err := manager.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("issue lease: %v", err)
	}
	input.Lease = leaseReferencePointer(lease)
	return lease, input
}

func leaseRequestForInput(input PolicyInput, grant PolicyDecision) LeaseRequest {
	return LeaseRequest{
		Principal: input.Principal, TenantID: input.Project.TenantID, ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion,
		TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role,
		Action: input.Action, Resource: input.Resource, ParameterDigest: input.ParameterDigest, Capabilities: []string{input.Action},
		PolicyVersion: testPolicyVersion, BudgetAccountID: input.Budget.AccountID, Grant: grant,
	}
}

func leaseCheckFor(lease CapabilityLease, at time.Time) LeaseCheck {
	return LeaseCheck{
		LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID, PrincipalID: lease.PrincipalID, PrincipalType: lease.PrincipalType,
		TenantID: lease.TenantID, ProjectID: lease.ProjectID, ProjectVersion: lease.ProjectVersion,
		TaskID: lease.TaskID, TaskVersion: lease.TaskVersion, SpecDigest: lease.SpecDigest, Role: lease.Role,
		Action: lease.Action, Resource: lease.Resource, ParameterDigest: lease.ParameterDigest,
		PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID, Capability: lease.Action,
		FencingToken: lease.FencingToken, At: at,
	}
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
	if _, err := manager.Heartbeat(context.Background(), LeaseHeartbeatRequest{LeaseID: lease.ID, TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID, PrincipalID: lease.PrincipalID, FencingToken: lease.FencingToken, Now: now}); err != nil {
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
	revoke := LeaseRevokeRequest{LeaseID: renewed.ID, ProjectID: renewed.ProjectID, TaskID: renewed.TaskID, Actor: testPrincipal(), Reason: "task canceled", RequestDigest: testParamsDigest, Now: now}
	if err := manager.Revoke(context.Background(), revoke); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := manager.Revoke(context.Background(), revoke); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	unauthorized := revoke
	unauthorized.Actor.ID = "agent_other"
	err = manager.Revoke(context.Background(), unauthorized)
	assertAuthzErrorCode(t, err, aorerrors.CodeForbidden)
	revoke.RequestDigest = testSpecDigest
	err = manager.Revoke(context.Background(), revoke)
	assertAuthzErrorCode(t, err, aorerrors.CodeIdempotencyConflict)
	decision, err = engine.Authorize(context.Background(), renewedInput)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("revoked lease accepted: decision=%#v err=%v", decision, err)
	}
	assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
}

func TestProjectAgentLeaseLifecycleDoesNotRequireTask(t *testing.T) {
	for _, role := range []string{authn.RoleGoalProposer, authn.RoleGoalChallenger, authn.RolePlanSupervisor, authn.RoleKnowledgeCurator} {
		t.Run(role, func(t *testing.T) {
			now := authzTestNow
			manager, _ := testManager(t, func() time.Time { return now })
			engine := testEngine(manager, func() time.Time { return now })
			input := PolicyInput{
				Principal: authn.Principal{ID: "agent_project", Type: authn.PrincipalAgentInstance, Role: role, TenantID: "tenant_1", ProjectID: "project_1"},
				Project:   ProjectScope{TenantID: "tenant_1", ID: "project_1", State: "GOAL_NEGOTIATING", StateVersion: 3, Classification: "INTERNAL"},
				Action:    ActionModelGenerate, Resource: Resource{Type: "model", ID: "model://goal/default"},
				ParameterDigest: testParamsDigest, Budget: BudgetScope{AccountID: "budget_1", Available: true},
			}
			lease, authorized := issueForInput(t, manager, engine, input, now)
			if lease.TaskID != "" || lease.TaskVersion != 0 || lease.SpecDigest != "" {
				t.Fatalf("project lease has task binding: %#v", lease)
			}
			if _, err := manager.Validate(context.Background(), leaseCheckFor(lease, now)); err != nil {
				t.Fatalf("validate project lease: %v", err)
			}
			if decision, err := engine.Authorize(context.Background(), authorized); err != nil || decision.Decision != DecisionAllow {
				t.Fatalf("authorize project lease: decision=%#v err=%v", decision, err)
			}
			now = now.Add(10 * time.Second)
			heartbeat, err := manager.Heartbeat(context.Background(), LeaseHeartbeatRequest{
				LeaseID: lease.ID, TenantID: lease.TenantID, ProjectID: lease.ProjectID,
				PrincipalID: lease.PrincipalID, FencingToken: lease.FencingToken,
			})
			if err != nil || !heartbeat.LastHeartbeatAt.Equal(now) {
				t.Fatalf("heartbeat project lease: lease=%#v err=%v", heartbeat, err)
			}
			if err := manager.Revoke(context.Background(), LeaseRevokeRequest{
				LeaseID: lease.ID, ProjectID: lease.ProjectID, Actor: input.Principal,
				Reason: "project run completed", RequestDigest: testSpecDigest,
			}); err != nil {
				t.Fatalf("revoke project lease: %v", err)
			}
		})
	}
}

func TestKnowledgeCuratorLeaseIsProjectScopedAndExactlyBound(t *testing.T) {
	now := authzTestNow
	manager, _ := testManager(t, func() time.Time { return now })
	engine := testEngine(manager, func() time.Time { return now })
	input := knowledgeCuratorInput()

	grant, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || grant.Decision != DecisionAllow || grant.Binding == nil {
		t.Fatalf("knowledge lease grant: decision=%#v err=%v", grant, err)
	}
	if grant.Binding.ProjectVersion != input.Project.StateVersion || grant.Binding.TaskID != "" || grant.Binding.TaskVersion != 0 || grant.Binding.SpecDigest != "" || grant.Binding.ParameterDigest != input.ParameterDigest {
		t.Fatalf("knowledge grant binding = %#v", grant.Binding)
	}
	wrongTypeRequest := leaseRequestForInput(input, grant)
	wrongTypeRequest.Principal.Type = authn.PrincipalAgentInstance
	if _, issueErr := manager.Issue(context.Background(), wrongTypeRequest); issueErr == nil {
		t.Fatal("knowledge lease issued to non-curator principal type")
	}

	lease, authorized := issueForInput(t, manager, engine, input, now)
	if lease.ProjectVersion != input.Project.StateVersion || lease.TaskID != "" || lease.TaskVersion != 0 || lease.SpecDigest != "" || lease.ParameterDigest != input.ParameterDigest {
		t.Fatalf("knowledge lease binding = %#v", lease)
	}
	if decision, authorizeErr := engine.Authorize(context.Background(), authorized); authorizeErr != nil || decision.Decision != DecisionAllow {
		t.Fatalf("knowledge write authorization: decision=%#v err=%v", decision, authorizeErr)
	}

	staleProject := authorized
	staleProject.Project.StateVersion++
	if decision, authorizeErr := engine.Authorize(context.Background(), staleProject); authorizeErr == nil || decision.Decision != DecisionDeny {
		t.Fatalf("stale project version accepted: decision=%#v err=%v", decision, authorizeErr)
	}

	changedProposal := authorized
	changedProposal.ParameterDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	changedProposal.Approval = &Approval{}
	*changedProposal.Approval = *authorized.Approval
	changedProposal.Approval.SubjectDigest = changedProposal.ParameterDigest
	if decision, authorizeErr := engine.Authorize(context.Background(), changedProposal); authorizeErr == nil || decision.Decision != DecisionDeny {
		t.Fatalf("changed proposal accepted: decision=%#v err=%v", decision, authorizeErr)
	}
}

func TestTaskModelLeaseLifecycleKeepsTaskBinding(t *testing.T) {
	now := authzTestNow
	manager, _ := testManager(t, func() time.Time { return now })
	engine := testEngine(manager, func() time.Time { return now })
	input := testInput()
	input.Principal.Role = authn.RoleModulePlanner
	input.Project.State = "PLANNING"
	input.Task.State = "PLANNING"
	input.Action = ActionModelGenerate
	input.Resource = Resource{Type: "model", ID: "model://planning/default"}

	lease, _ := issueForInput(t, manager, engine, input, now)
	if lease.TaskID != input.Task.ID || lease.TaskVersion != input.Task.StateVersion || lease.SpecDigest != input.Task.SpecDigest {
		t.Fatalf("task model lease lost binding: %#v", lease)
	}
	if _, err := manager.Validate(context.Background(), leaseCheckFor(lease, now)); err != nil {
		t.Fatalf("validate task model lease: %v", err)
	}
}

func TestTaskAgentLeaseStillRequiresTask(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	input := testInput()
	input.Task = TaskScope{}
	if _, err := engine.EvaluateLeaseGrant(context.Background(), input); err == nil {
		t.Fatal("task-scoped role received a project lease grant")
	}
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

func TestLeaseIssueUsesTrustedTime(t *testing.T) {
	trustedNow := authzTestNow
	for _, test := range []struct {
		name   string
		forged time.Time
	}{
		{name: "past", forged: trustedNow.Add(-time.Minute)},
		{name: "future", forged: trustedNow.Add(time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, _ := testManager(t, func() time.Time { return trustedNow })
			engine := testEngine(manager, func() time.Time { return trustedNow })
			input := testInput()
			grant, err := engine.EvaluateLeaseGrant(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			request := leaseRequestForInput(input, grant)
			request.TTL = time.Minute
			request.HeartbeatInterval = 10 * time.Second
			request.Now = test.forged
			lease, err := manager.Issue(context.Background(), request)
			if err != nil {
				t.Fatalf("issue with forged caller time: %v", err)
			}
			if !lease.IssuedAt.Equal(trustedNow) || !lease.LastHeartbeatAt.Equal(trustedNow) || !lease.ExpiresAt.Equal(trustedNow.Add(time.Minute)) {
				t.Fatalf("lease used caller time: issued=%s heartbeat=%s expires=%s", lease.IssuedAt, lease.LastHeartbeatAt, lease.ExpiresAt)
			}
		})
	}
}

func TestLeaseRenewUsesTrustedTime(t *testing.T) {
	t.Run("future cannot extend", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(10 * time.Second)
		grant, err := engine.EvaluateLeaseGrant(context.Background(), testInput())
		if err != nil {
			t.Fatal(err)
		}
		renewed, err := manager.Renew(context.Background(), LeaseRenewalRequest{
			LeaseID: lease.ID, FencingToken: lease.FencingToken, PrincipalID: lease.PrincipalID,
			PrincipalType: lease.PrincipalType, Role: lease.Role, PolicyVersion: lease.PolicyVersion,
			TTL: 3 * time.Minute, Grant: grant, Now: trustedNow.Add(time.Minute),
		})
		if err != nil {
			t.Fatalf("renew with forged future time: %v", err)
		}
		if !renewed.LastHeartbeatAt.Equal(trustedNow) || !renewed.ExpiresAt.Equal(trustedNow.Add(3*time.Minute)) {
			t.Fatalf("renewal used caller time: heartbeat=%s expires=%s", renewed.LastHeartbeatAt, renewed.ExpiresAt)
		}
	})

	t.Run("past cannot revive", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(90 * time.Second)
		grant, err := engine.EvaluateLeaseGrant(context.Background(), testInput())
		if err != nil {
			t.Fatal(err)
		}
		_, err = manager.Renew(context.Background(), LeaseRenewalRequest{
			LeaseID: lease.ID, FencingToken: lease.FencingToken, PrincipalID: lease.PrincipalID,
			PrincipalType: lease.PrincipalType, Role: lease.Role, PolicyVersion: lease.PolicyVersion,
			Grant: grant, Now: authzTestNow.Add(10 * time.Second),
		})
		assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
	})
}

func TestLeaseHeartbeatUsesTrustedTime(t *testing.T) {
	t.Run("future cannot extend", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(10 * time.Second)
		updated, err := manager.Heartbeat(context.Background(), LeaseHeartbeatRequest{
			LeaseID: lease.ID, TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID,
			PrincipalID: lease.PrincipalID, FencingToken: lease.FencingToken,
			Now: trustedNow.Add(4 * time.Minute),
		})
		if err != nil {
			t.Fatalf("heartbeat with forged future time: %v", err)
		}
		if !updated.LastHeartbeatAt.Equal(trustedNow) {
			t.Fatalf("heartbeat used caller time: %s", updated.LastHeartbeatAt)
		}
	})

	t.Run("past cannot revive", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(90 * time.Second)
		_, err := manager.Heartbeat(context.Background(), LeaseHeartbeatRequest{
			LeaseID: lease.ID, TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID,
			PrincipalID: lease.PrincipalID, FencingToken: lease.FencingToken,
			Now: authzTestNow.Add(10 * time.Second),
		})
		assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
	})
}

func TestLeaseRevokeUsesTrustedTime(t *testing.T) {
	for _, test := range []struct {
		name   string
		forged time.Time
	}{
		{name: "past", forged: authzTestNow.Add(-time.Hour)},
		{name: "future", forged: authzTestNow.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			trustedNow := authzTestNow
			manager, _ := testManager(t, func() time.Time { return trustedNow })
			engine := testEngine(manager, func() time.Time { return trustedNow })
			lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
			trustedNow = trustedNow.Add(20 * time.Second)
			if err := manager.Revoke(context.Background(), LeaseRevokeRequest{LeaseID: lease.ID, ProjectID: lease.ProjectID, TaskID: lease.TaskID, Actor: testPrincipal(), Reason: "trusted-time test", RequestDigest: testParamsDigest, Now: test.forged}); err != nil {
				t.Fatal(err)
			}
			revoked, found, err := manager.Get(context.Background(), lease.ID)
			if err != nil || !found || revoked.RevokedAt == nil {
				t.Fatalf("load revoked lease: found=%v lease=%#v err=%v", found, revoked, err)
			}
			if !revoked.RevokedAt.Equal(trustedNow) {
				t.Fatalf("revocation used caller time: %s", *revoked.RevokedAt)
			}
		})
	}
}

func TestLeaseValidateUsesTrustedTime(t *testing.T) {
	t.Run("future cannot expire", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(10 * time.Second)
		validated, err := manager.Validate(context.Background(), leaseCheckFor(lease, trustedNow.Add(24*time.Hour)))
		if err != nil || validated.State != LeaseActive {
			t.Fatalf("forged future expired active lease: lease=%#v err=%v", validated, err)
		}
	})

	t.Run("past cannot bypass expiry", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(90 * time.Second)
		_, err := manager.Validate(context.Background(), leaseCheckFor(lease, authzTestNow.Add(10*time.Second)))
		assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
	})
}

func TestLeaseValidateActiveUsesTrustedTime(t *testing.T) {
	t.Run("future cannot expire", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(10 * time.Second)
		validated, err := manager.ValidateActive(context.Background(), lease.ID, trustedNow.Add(24*time.Hour))
		if err != nil || validated.State != LeaseActive {
			t.Fatalf("forged future expired active lease: lease=%#v err=%v", validated, err)
		}
	})

	t.Run("past cannot bypass expiry", func(t *testing.T) {
		trustedNow := authzTestNow
		manager, _ := testManager(t, func() time.Time { return trustedNow })
		engine := testEngine(manager, func() time.Time { return trustedNow })
		lease, _ := issueForInput(t, manager, engine, testInput(), trustedNow)
		trustedNow = trustedNow.Add(90 * time.Second)
		_, err := manager.ValidateActive(context.Background(), lease.ID, authzTestNow.Add(10*time.Second))
		assertAuthzErrorCode(t, err, aorerrors.CodeLeaseExpired)
	})
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

func TestLeasePersistsOnlyNonceDigest(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	lease, _ := issueForInput(t, manager, engine, testInput(), authzTestNow)
	if !digestPattern.MatchString(lease.Nonce) {
		t.Fatalf("nonce is not a digest: %q", lease.Nonce)
	}
}

func TestMemoryLeaseStoreHonorsTenantContext(t *testing.T) {
	manager, store := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	lease, _ := issueForInput(t, manager, engine, testInput(), authzTestNow)
	if _, found, err := store.Get(withLeaseTenant(context.Background(), "tenant_other"), lease.ID); err != nil || found {
		t.Fatalf("cross-tenant lease lookup: found=%v err=%v", found, err)
	}
	loaded, found, err := store.Get(withLeaseTenant(context.Background(), lease.TenantID), lease.ID)
	if err != nil || !found || loaded.ID != lease.ID {
		t.Fatalf("same-tenant lease lookup: found=%v lease=%#v err=%v", found, loaded, err)
	}
}

func TestPostgresLeaseCASRejectsBindingMutation(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	lease, _ := issueForInput(t, manager, engine, testInput(), authzTestNow)
	renewed := cloneLease(lease)
	renewed.ExpiresAt = renewed.ExpiresAt.Add(time.Minute)
	renewed.FencingToken++
	if !sameLeaseBinding(lease, renewed) {
		t.Fatal("valid lease lifecycle update changed immutable binding")
	}
	renewed.Resource.Path = "internal/state/project.go"
	if sameLeaseBinding(lease, renewed) {
		t.Fatal("mutated resource retained the lease binding")
	}
}

func assertAuthzErrorCode(t *testing.T, err error, expected aorerrors.Code) {
	t.Helper()
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != expected {
		t.Fatalf("expected %s, got %v", expected, err)
	}
}
