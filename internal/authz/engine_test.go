package authz

import (
	"context"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestEngineFailsClosedForUnavailableOrMalformedPolicyFacts(t *testing.T) {
	input := testInput()
	unavailable := NewEngine(EngineConfig{Bundle: PolicyBundle{Version: testPolicyVersion, Available: false}, Clock: func() time.Time { return authzTestNow }})
	decision, err := unavailable.Evaluate(context.Background(), input)
	if decision.Decision != DecisionDeny {
		t.Fatalf("unavailable policy did not deny: %#v", decision)
	}
	assertAuthzErrorCode(t, err, aorerrors.CodeDependencyUnavailable)

	available := testEngine(nil, func() time.Time { return authzTestNow })
	input.Project.TenantID = "tenant_2"
	decision, err = available.Evaluate(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("cross-tenant input accepted: decision=%#v err=%v", decision, err)
	}

	input = testInput()
	input.Task.ProjectID = "project_2"
	decision, err = available.Evaluate(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("cross-project task accepted: decision=%#v err=%v", decision, err)
	}

	input = testInput()
	input.Resource.Attributes = map[string]string{"provider_api_key": "must-not-enter-policy"}
	decision, err = available.Evaluate(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("credential-shaped resource attribute accepted: decision=%#v err=%v", decision, err)
	}

	input = testInput()
	input.Resource.Path = "internal/auth/../state/project.go"
	decision, err = available.Evaluate(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("path traversal accepted: decision=%#v err=%v", decision, err)
	}
}

func TestApprovalProofIsRequired(t *testing.T) {
	input := testInput()
	input.Principal = authn.Principal{ID: "curator_1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator, TenantID: "tenant_1", ProjectID: "project_1"}
	input.Action = ActionKnowledgeWrite
	input.Resource = Resource{Type: "knowledge.write", Path: "knowledge/global/rules.md"}
	input.Approval = &Approval{ID: "approval_1", TenantID: input.Project.TenantID, ProjectID: input.Project.ID, PrincipalID: "user_1", SubjectType: input.Action, SubjectID: input.Resource.Path, SubjectVersion: input.Task.StateVersion, SubjectDigest: input.ParameterDigest, IssuedAt: authzTestNow.Add(-time.Minute), ExpiresAt: authzTestNow.Add(time.Minute), Signature: "unverified-signature"}
	engine := NewEngine(EngineConfig{Bundle: PolicyBundle{Version: testPolicyVersion, Digest: testPolicyVersion, Available: true}, Clock: func() time.Time { return authzTestNow }})
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("approval without verifier accepted: decision=%#v err=%v", decision, err)
	}
	assertAuthzErrorCode(t, err, aorerrors.CodeDependencyUnavailable)
}

func TestBreakGlassRequiresTwoDistinctApprovers(t *testing.T) {
	input := testInput()
	input.Principal = authn.Principal{ID: "admin_1", Type: authn.PrincipalBreakGlassAdmin, Role: authn.RoleBreakGlassAdmin, TenantID: "tenant_1", ProjectID: "project_1"}
	input.Action = ActionPolicyWrite
	input.Resource = Resource{Type: "policy.write", ID: "bundle_next"}
	input.Approval = &Approval{ID: "approval_1", TenantID: input.Project.TenantID, ProjectID: input.Project.ID, PrincipalID: "security_approver", SubjectType: input.Action, SubjectID: input.Resource.ID, SubjectVersion: input.Task.StateVersion, SubjectDigest: input.ParameterDigest, IssuedAt: authzTestNow.Add(-time.Minute), ExpiresAt: authzTestNow.Add(time.Minute), Signature: "signed-approval"}
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionApprovalRequired {
		t.Fatalf("single break-glass approver result: decision=%#v err=%v", decision, err)
	}
	input.Approval.CoApproverID = "platform_approver"
	decision, err = engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("two distinct approvers rejected: decision=%#v err=%v", decision, err)
	}
}

func TestEngineRequiresCurrentLeaseAndExactCommitFacts(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	input := testInput()
	decision, err := engine.Evaluate(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("write without lease accepted: decision=%#v err=%v", decision, err)
	}

	_, authorized := issueForInput(t, manager, engine, input, authzTestNow)
	changed := authorized
	changed.ParameterDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	decision, err = engine.Evaluate(context.Background(), changed)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("changed parameters accepted: decision=%#v err=%v", decision, err)
	}

	changed = authorized
	changed.Resource.Path = "internal/state/project.go"
	decision, err = engine.Evaluate(context.Background(), changed)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("changed resource accepted: decision=%#v err=%v", decision, err)
	}

	changed = authorized
	changed.Task.StateVersion++
	decision, err = engine.Evaluate(context.Background(), changed)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("stale task version accepted: decision=%#v err=%v", decision, err)
	}

	changed = authorized
	changed.Budget.Available = false
	decision, err = engine.Evaluate(context.Background(), changed)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("unavailable budget accepted: decision=%#v err=%v", decision, err)
	}
}

func TestDefaultPolicyRoleOwnershipAndApproval(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })

	unowned := testInput()
	unowned.Resource.Path = "internal/state/project.go"
	decision, err := engine.EvaluateLeaseGrant(context.Background(), unowned)
	if err != nil || decision.Decision != DecisionDeny {
		t.Fatalf("unowned path result: decision=%#v err=%v", decision, err)
	}

	auditor := testInput()
	auditor.Principal.Type = authn.PrincipalAgentInstance
	auditor.Principal.Role = authn.RoleAuditor
	decision, err = engine.EvaluateLeaseGrant(context.Background(), auditor)
	if err != nil || decision.Decision != DecisionDeny {
		t.Fatalf("auditor write result: decision=%#v err=%v", decision, err)
	}

	curator := testInput()
	curator.Principal = authn.Principal{ID: "curator_1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator, TenantID: "tenant_1", ProjectID: "project_1"}
	curator.Action = ActionKnowledgeWrite
	curator.Resource = Resource{Type: "knowledge.write", Path: "knowledge/global/rules.md"}
	curator.Task.OwnedPaths = nil
	decision, err = engine.EvaluateLeaseGrant(context.Background(), curator)
	if err != nil || decision.Decision != DecisionApprovalRequired {
		t.Fatalf("missing curator approval result: decision=%#v err=%v", decision, err)
	}
	curator.Approval = &Approval{ID: "approval_1", TenantID: curator.Project.TenantID, ProjectID: curator.Project.ID, PrincipalID: "user_1", SubjectType: ActionKnowledgeWrite, SubjectID: curator.Resource.Path, SubjectVersion: curator.Task.StateVersion, SubjectDigest: curator.ParameterDigest, IssuedAt: authzTestNow.Add(-time.Minute), ExpiresAt: authzTestNow.Add(time.Minute), Signature: "signed-approval"}
	decision, err = engine.EvaluateLeaseGrant(context.Background(), curator)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("valid curator approval rejected: decision=%#v err=%v", decision, err)
	}
}

func TestProductionUntrustedExecutionRequiresLinuxContainer(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	input := testInput()
	input.Resource.Attributes = map[string]string{"environment": "production", "workloadTrust": "UNTRUSTED"}
	input.Context = ExecutionContext{Platform: "WINDOWS", SandboxLevel: "NONE"}
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("untrusted Windows workload accepted: decision=%#v err=%v", decision, err)
	}
	assertAuthzErrorCode(t, err, aorerrors.CodeSandboxLevelInsufficient)
}

func TestUnknownActionsRemainDenied(t *testing.T) {
	input := testInput()
	input.Action = "future.read"
	input.Lease = nil
	input.ParameterDigest = ""
	input.Budget = BudgetScope{}
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	decision, err := engine.Evaluate(context.Background(), input)
	if err != nil || decision.Decision != DecisionDeny || decision.ReasonCodes[0] != "UNKNOWN_ACTION" {
		t.Fatalf("unknown action result: decision=%#v err=%v", decision, err)
	}
}

func TestProjectReadDoesNotInventTaskScope(t *testing.T) {
	input := testInput()
	input.Action = ActionGoalRead
	input.Task = TaskScope{}
	input.Resource = Resource{Type: "goal", ID: "goal_1"}
	input.ParameterDigest = ""
	input.Budget = BudgetScope{}
	input.Context = ExecutionContext{}
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	decision, err := engine.Evaluate(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("project-scoped read rejected: decision=%#v err=%v", decision, err)
	}
}

func TestCustomAllowCannotOverrideDefaultDeny(t *testing.T) {
	input := testInput()
	input.Resource.Path = "internal/state/project.go"
	engine := NewEngine(EngineConfig{Bundle: PolicyBundle{Version: testPolicyVersion, Digest: testPolicyVersion, Available: true, Rules: []Rule{RuleFunc(func(PolicyInput) (PolicyDecision, bool) {
		return allowDecision(testPolicyVersion, "custom.allow", "CUSTOM_ALLOWED"), true
	})}}, Clock: func() time.Time { return authzTestNow }})
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionDeny || decision.ReasonCodes[0] != "TASK_DOES_NOT_OWN_PATH" {
		t.Fatalf("custom rule widened default policy: decision=%#v err=%v", decision, err)
	}
}
