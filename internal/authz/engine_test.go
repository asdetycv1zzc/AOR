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
	input := knowledgeCuratorInput()
	input.Approval.Signature = "unverified-signature"
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

	curator := knowledgeCuratorInput()
	curator.Approval = nil
	decision, err = engine.EvaluateLeaseGrant(context.Background(), curator)
	if err != nil || decision.Decision != DecisionApprovalRequired {
		t.Fatalf("missing curator approval result: decision=%#v err=%v", decision, err)
	}
	curator.Approval = knowledgeCuratorInput().Approval
	decision, err = engine.EvaluateLeaseGrant(context.Background(), curator)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("valid curator approval rejected: decision=%#v err=%v", decision, err)
	}
}

func TestKnowledgeCuratorGrantRequiresProjectApprovalAndExactIdentity(t *testing.T) {
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	input := knowledgeCuratorInput()

	for name, mutate := range map[string]func(*PolicyInput){
		"task scope":             func(candidate *PolicyInput) { candidate.Task = testInput().Task },
		"stale project approval": func(candidate *PolicyInput) { candidate.Approval.SubjectVersion-- },
		"wrong proposal digest":  func(candidate *PolicyInput) { candidate.Approval.SubjectDigest = testSpecDigest },
		"wrong project":          func(candidate *PolicyInput) { candidate.Approval.ProjectID = "project_2" },
		"wrong principal type":   func(candidate *PolicyInput) { candidate.Principal.Type = authn.PrincipalAgentInstance },
		"wrong curator role":     func(candidate *PolicyInput) { candidate.Principal.Role = authn.RoleExecutor },
		"unavailable budget":     func(candidate *PolicyInput) { candidate.Budget.Available = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := knowledgeCuratorInput()
			mutate(&candidate)
			decision, err := engine.EvaluateLeaseGrant(context.Background(), candidate)
			if decision.Decision == DecisionAllow {
				t.Fatalf("invalid curator grant allowed: decision=%#v err=%v", decision, err)
			}
		})
	}

	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow || decision.Binding == nil || decision.Binding.ProjectVersion != input.Project.StateVersion || decision.Binding.TaskID != "" {
		t.Fatalf("valid project curator grant: decision=%#v err=%v", decision, err)
	}
}

func TestSandboxExecutionLeaseGrantBindsRoleAndState(t *testing.T) {
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	input := testInput()
	input.Action = ActionSandboxExec
	input.Resource = Resource{Type: "sandbox", ID: "sandbox_1"}
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow || decision.Binding == nil || decision.Binding.Action != ActionSandboxExec {
		t.Fatalf("sandbox lease grant = %#v, err=%v", decision, err)
	}

	input.Task.State = "CANCELED"
	decision, err = engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionDeny {
		t.Fatalf("canceled task sandbox grant = %#v, err=%v", decision, err)
	}

	input.Task.State = "DETERMINISTIC_AUDIT"
	input.Principal.Role = authn.RoleAuditor
	decision, err = engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("auditor sandbox grant = %#v, err=%v", decision, err)
	}
}

func TestToolLeaseGrantRejectsTerminalTaskAndPausedProject(t *testing.T) {
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	input := testInput()
	input.Action = ActionToolInvoke
	input.Resource = Resource{Type: "tool", ID: "tool://repository/repo.read@1.0.0"}

	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionAllow || decision.Binding == nil {
		t.Fatalf("active tool lease grant = %#v, err=%v", decision, err)
	}

	input.Task.State = "CANCELED"
	decision, err = engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionDeny || decision.ReasonCodes[0] != "TASK_NOT_ACTIVE" {
		t.Fatalf("canceled task tool grant = %#v, err=%v", decision, err)
	}

	input.Task.State = "EXECUTING"
	input.Project.State = "PAUSED"
	decision, err = engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionDeny || decision.ReasonCodes[0] != "TASK_NOT_ACTIVE" {
		t.Fatalf("paused project tool grant = %#v, err=%v", decision, err)
	}
}

func TestTaskModelLeaseGrantBindsActiveTask(t *testing.T) {
	engine := testEngine(nil, func() time.Time { return authzTestNow })
	for _, role := range []string{authn.RoleModulePlanner, authn.RoleExecutor, authn.RoleAuditor, "MODULE_AUDITOR"} {
		t.Run(role, func(t *testing.T) {
			input := testInput()
			input.Principal.Role = role
			input.Project.State = "PLANNING"
			input.Task.State = "PLANNING"
			input.Action = ActionModelGenerate
			input.Resource = Resource{Type: "model", ID: "model://planning/default"}

			decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
			if err != nil || decision.Decision != DecisionAllow || decision.Binding == nil || decision.Binding.TaskID != input.Task.ID || decision.Binding.TaskVersion != input.Task.StateVersion || decision.Binding.SpecDigest != input.Task.SpecDigest {
				t.Fatalf("task model lease grant = %#v, err=%v", decision, err)
			}
		})
	}

	input := testInput()
	input.Principal.Role = authn.RoleModulePlanner
	input.Action = ActionModelGenerate
	input.Resource = Resource{Type: "model", ID: "model://planning/default"}
	input.Task.State = "CANCELED"
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != DecisionDeny || decision.ReasonCodes[0] != "MODEL_SCOPE_DENIED" {
		t.Fatalf("terminal task model grant = %#v, err=%v", decision, err)
	}

	input.Task = TaskScope{}
	if _, err = engine.EvaluateLeaseGrant(context.Background(), input); err == nil {
		t.Fatal("task model lease grant accepted without task scope")
	}
}

func TestProductionUntrustedExecutionRequiresLinuxContainer(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return authzTestNow })
	engine := testEngine(manager, func() time.Time { return authzTestNow })
	input := testInput()
	input.Task.ExecutionPlatform = "WINDOWS"
	input.Task.SandboxLevel = "NONE"
	input.Task.WorkloadTrust = "UNTRUSTED"
	input.Task.DeploymentProfile = "PRODUCTION"
	input.Resource.Attributes = map[string]string{"environment": "local", "workloadTrust": "TRUSTED"}
	input.Context = ExecutionContext{Platform: "WINDOWS", SandboxLevel: "NONE"}
	decision, err := engine.EvaluateLeaseGrant(context.Background(), input)
	if decision.Decision != DecisionDeny || err == nil {
		t.Fatalf("spoofed resource attributes bypassed trusted execution scope: decision=%#v err=%v", decision, err)
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
