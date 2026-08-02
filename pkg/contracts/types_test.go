package contracts

import "testing"

func TestModuleTaskDoneIsComputedFromIntegratedEvidence(t *testing.T) {
	evidence := CompletionEvidence{SubmissionImmutable: true, AuditPassed: true, MergeQueued: true, NoBlockingFindings: true, RequiredEvidence: true}
	if evidence.Done(TaskPassed) {
		t.Fatal("passed task is not complete before integration")
	}
	if !evidence.Done(TaskIntegrated) {
		t.Fatal("integrated task with complete evidence should be done")
	}
}

func TestModuleSpecRejectsWindowsIsolationClaims(t *testing.T) {
	spec := ModuleSpec{
		ModuleSpecVersion: 1,
		ModuleID:          "mod_1",
		ProjectID:         "prj_1",
		PlanVersion:       1,
		ExecutionPlatform: PlatformWindows,
		SandboxLevel:      IsolationNone,
		NetworkPolicy:     NetworkPolicy{Mode: NetworkAllowlist, Destinations: []string{"example.test"}},
	}
	if err := spec.Validate(); err == nil {
		t.Fatal("windows NONE must reject claimed network isolation")
	}
}

func TestSubmissionRequiresAttemptSeriesAndBoundedAttempt(t *testing.T) {
	manifest := SubmissionManifest{SubmissionVersion: 1, ProjectID: "prj_1", ModuleTaskID: "task_1", Attempt: 4, BaseCommit: "0000000000000000000000000000000000000001", HeadCommit: "0000000000000000000000000000000000000002", SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := manifest.Validate(); err == nil {
		t.Fatal("attempt four must be rejected")
	}
}

func TestApprovedGoalRequiresUserApprovalAndNoUnresolvedItems(t *testing.T) {
	goal := GoalSpec{Content: GoalContent{GoalSpecVersion: 1, ProjectID: "prj_1", Version: 1, UnresolvedItems: []string{"open"}}, Status: GoalApproved, ContentSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := goal.Validate(); err == nil {
		t.Fatal("unresolved approved goal must be rejected")
	}
}

func TestGoalRejectsUnknownStatus(t *testing.T) {
	goal := GoalSpec{Content: GoalContent{GoalSpecVersion: 1, ProjectID: "prj_1", Version: 1, Title: "Goal", Summary: "Summary", ProblemStatement: "Problem", BusinessOutcomes: []Outcome{{ID: "outcome_1", Statement: "Outcome"}}, AcceptanceCriteria: []AcceptanceCriterion{{ID: "criterion_1", Statement: "Pass", EvidenceType: "AUTOMATED"}}, CreatedAt: "2030-01-01T00:00:00Z", CreatedBy: AgentIdentity{AgentInstanceID: "agt_1", Role: "GOAL_PROPOSER"}}, Status: GoalStatus("UNKNOWN"), ContentSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := goal.Validate(); err == nil {
		t.Fatal("unknown GoalStatus must be rejected")
	}
}

func TestLinuxModuleRejectsUnrestrictedNetwork(t *testing.T) {
	spec := ModuleSpec{ModuleSpecVersion: 1, ModuleID: "mod_1", ProjectID: "prj_1", PlanVersion: 1, Name: "module", Purpose: "purpose", ExecutionPlatform: PlatformLinux, SandboxLevel: IsolationContainer, NetworkPolicy: NetworkPolicy{Mode: NetworkUnrestricted}, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := spec.Validate(); err == nil {
		t.Fatal("Linux module accepted unrestricted network")
	}
}
