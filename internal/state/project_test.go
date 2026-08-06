package state

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestGoalApprovalRequiresExactDigestUserAndNoUnresolvedItems(t *testing.T) {
	project := createProject(t)
	goal := GoalRecord{ID: "goal_1", Version: 1, SHA256: digestZero(), UnresolvedItems: []string{"decision"}}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandProposeGoal, Goal: &goal, ActorID: "agt_goal", At: testTime()})

	_, err := DecideProject(project, ProjectCommand{Type: ProjectCommandApproveGoal, Goal: &goal, ActorID: "usr_1", Approval: goalApproval(goal, "usr_1"), At: testTime()})
	if err == nil || err.Code != aorerrors.CodeGoalNotApproved {
		t.Fatalf("unresolved goal approval = %#v", err)
	}

	goal.UnresolvedItems = nil
	wrong := goal
	wrong.SHA256 = digestOne()
	_, err = DecideProject(project, ProjectCommand{Type: ProjectCommandApproveGoal, Goal: &wrong, ActorID: "usr_1", Approval: goalApproval(wrong, "usr_1"), At: testTime()})
	if err == nil || err.Code != aorerrors.CodeGoalHashMismatch {
		t.Fatalf("wrong hash approval = %#v", err)
	}

	project.Goal.UnresolvedItems = nil
	wrongPrincipal := goalApproval(goal, "usr_2")
	_, err = DecideProject(project, ProjectCommand{Type: ProjectCommandApproveGoal, Goal: &goal, ActorID: "usr_1", Approval: wrongPrincipal, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeApprovalRequired {
		t.Fatalf("wrong approval principal = %#v", err)
	}

	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandApproveGoal, Goal: &goal, ActorID: "usr_1", Approval: goalApproval(goal, "usr_1"), At: testTime()})
	if project.State != contracts.ProjectPlanning || project.Goal.ApprovedBy != "usr_1" || project.Goal.ApprovalRecordID != "approval_1" {
		t.Fatalf("approved project = %#v", project)
	}
}

func TestProjectCreationPrecedesGoalNegotiation(t *testing.T) {
	event, err := DecideProject(Project{}, ProjectCommand{Type: ProjectCommandCreate, TenantID: "tenant_1", ProjectID: "prj_created", ActorID: "usr_1", GoalAgentCount: 1, At: testTime()})
	if err != nil {
		t.Fatal(err)
	}
	project, applyErr := ApplyProject(Project{}, event)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if project.State != contracts.ProjectCreated {
		t.Fatalf("created state = %s", project.State)
	}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandStartGoalNegotiation, ActorID: "svc_orchestrator", At: testTime()})
	if project.State != contracts.ProjectGoalNegotiating {
		t.Fatalf("negotiating state = %s", project.State)
	}
}

func TestProjectCreationCanCommitCompleteInitializationSelection(t *testing.T) {
	event, err := DecideProject(Project{}, ProjectCommand{
		Type: ProjectCommandCreate, TenantID: "tenant_1", ProjectID: "prj_initialized", ActorID: "usr_1",
		GoalAgentCount: 2, DataClassification: "CONFIDENTIAL", DeploymentTargets: []string{"test-linux", "pre-production"},
		BudgetCurrency: "USD", BudgetHardLimitMinor: 100000, BudgetSoftLimitMinor: 80000,
		PromptBundleVersion: "1.0.0", StartGoalNegotiation: true, At: testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	project := event.Projection
	if event.Type != "io.aor.goal.negotiation-started.v1" || project.State != contracts.ProjectGoalNegotiating || project.Version != 1 || project.BudgetCurrency != "USD" || project.BudgetHardLimitMinor != 100000 || project.BudgetSoftLimitMinor != 80000 || project.PromptBundleVersion != "1.0.0" || len(project.DeploymentTargets) != 2 {
		t.Fatalf("initialized project = %#v event=%q", project, event.Type)
	}
	applied, applyErr := ApplyProject(Project{}, event)
	if applyErr != nil || applied.DeploymentTargets[0] != "test-linux" {
		t.Fatalf("project clone = %#v err=%v", applied, applyErr)
	}
	applied.DeploymentTargets[0] = "mutated"
	if event.Projection.DeploymentTargets[0] != "test-linux" {
		t.Fatalf("project deployment targets alias event: %#v", event.Projection.DeploymentTargets)
	}
}

func TestProjectCannotCompleteWithoutReleaseApprovalAndEvidence(t *testing.T) {
	project := Project{TenantID: "tenant_1", ID: "prj_1", State: contracts.ProjectGlobalAudit, Version: 8}
	_, err := DecideProject(project, ProjectCommand{Type: ProjectCommandComplete, ActorID: "svc_orchestrator", Completion: &CompletionFacts{AllTasksIntegrated: true, GoalCriteriaSatisfied: true, GlobalAuditPassed: true, ReleaseArtifactsSigned: true, NoBlockingFindings: true, EvidenceSHA256: digestZero()}, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeInvalidStateTransition {
		t.Fatalf("unsigned completion = %#v", err)
	}
}

func TestProjectCompletionRequiresEveryAuthoritativeGate(t *testing.T) {
	goal := &GoalRecord{ID: "goal_1", Version: 1, SHA256: digestZero(), Status: contracts.GoalApproved, ApprovedBy: "usr_1", ApprovalRecordID: "goal_approval_1"}
	plan := &contracts.SpecRef{Version: 1, SHA256: digestOne()}
	project := Project{TenantID: "tenant_1", ID: "prj_1", State: contracts.ProjectGlobalAudit, Version: 8, Goal: goal, Plan: plan, ReleaseApprovalRecordID: "release_approval_1"}
	complete := CompletionFacts{
		AllTasksIntegrated: true, AllIntegrationTasksDone: true, IntegrationAuditPassed: true,
		GoalCriteriaSatisfied: true, GlobalAuditPassed: true, ReleaseGatesPassed: true,
		ReleaseArtifactsSigned: true, SBOMGenerated: true, ProvenanceGenerated: true,
		NoBlockedOrRework: true, NoBlockingFindings: true, OperationalSummariesGenerated: true,
		PlanSupervisorSummaryGenerated: true, GoalSummaryVerified: true, FinalResultDelivered: true,
		EvidenceSHA256: digestZero(),
	}
	event, err := DecideProject(project, ProjectCommand{Type: ProjectCommandComplete, ActorID: "svc_orchestrator", Completion: &complete, At: testTime()})
	if err != nil || event.Projection.State != contracts.ProjectCompleted {
		t.Fatalf("complete project=%#v err=%v", event.Projection, err)
	}

	withoutIntegrationTasks := complete
	withoutIntegrationTasks.AllIntegrationTasksDone = false
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandComplete, ActorID: "svc_orchestrator", Completion: &withoutIntegrationTasks, At: testTime()}); err == nil {
		t.Fatal("completion accepted unfinished IntegrationTask")
	}
	acceptedRisk := complete
	acceptedRisk.NoBlockingFindings = false
	acceptedRisk.RiskAcceptancesValid = true
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandComplete, ActorID: "svc_orchestrator", Completion: &acceptedRisk, At: testTime()}); err != nil {
		t.Fatalf("compliant risk acceptance rejected: %v", err)
	}
	invalidRisk := acceptedRisk
	invalidRisk.RiskAcceptancesValid = false
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandComplete, ActorID: "svc_orchestrator", Completion: &invalidRisk, At: testTime()}); err == nil {
		t.Fatal("completion accepted unresolved high risk")
	}
}

func TestProjectArchiveRequiresTerminalOutcome(t *testing.T) {
	project := createProject(t)
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandArchive, ActorID: "usr_1", At: testTime()}); err == nil || err.Code != aorerrors.CodeInvalidStateTransition {
		t.Fatalf("active project archive = %#v", err)
	}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandAbort, ActorID: "usr_1", At: testTime()})
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandArchive, ActorID: "usr_1", At: testTime()})
	if project.State != contracts.ProjectArchived {
		t.Fatalf("archived state = %s", project.State)
	}
}

func TestProjectDeletionStopsWorkAndRequiresLegalHoldRelease(t *testing.T) {
	project := createProject(t)
	hold := ProjectLegalHold{ID: "hold_1", Reason: "active litigation", PlacedBy: "compliance_1", PlacedAt: testTime()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandPlaceLegalHold, ActorID: "compliance_1", LegalHold: &hold, At: testTime()})
	deletion := ProjectDeletion{ID: "deletion_1", RequestedBy: "usr_1", RequestedAt: testTime(), EarliestExecutionAt: testTime()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandRequestDeletion, ActorID: "usr_1", Deletion: &deletion, At: testTime()})
	if project.State != contracts.ProjectPaused || project.Deletion == nil || project.Deletion.Status != ProjectDeletionBlocked {
		t.Fatalf("blocked deletion = %#v", project)
	}
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandResume, ActorID: "usr_1", At: testTime()}); err == nil || err.Code != aorerrors.CodeInvalidStateTransition {
		t.Fatalf("resume after deletion request = %#v", err)
	}
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandBeginDeletion, ActorID: "svc_retention", At: testTime()}); err == nil || err.Code != aorerrors.CodeInvalidStateTransition {
		t.Fatalf("deletion under legal hold = %#v", err)
	}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandReleaseLegalHold, ActorID: "compliance_2", LegalHoldID: hold.ID, ReleaseReason: "matter closed", At: testTime()})
	if project.Deletion.Status != ProjectDeletionReady || project.LegalHolds[0].ReleasedAt == nil {
		t.Fatalf("released hold = %#v", project)
	}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandBeginDeletion, ActorID: "svc_retention", At: testTime()})
	if project.Deletion.Status != ProjectDeletionErasing || project.Deletion.StartedAt == nil {
		t.Fatalf("started deletion = %#v", project.Deletion)
	}
}

func TestProjectDeletionAndLegalHoldSurviveDurableJSONRoundTrip(t *testing.T) {
	project := createProject(t)
	hold := ProjectLegalHold{ID: "hold_1", Reason: "records request", PlacedBy: "compliance_1", PlacedAt: testTime()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandPlaceLegalHold, ActorID: "compliance_1", LegalHold: &hold, At: testTime()})
	deletion := ProjectDeletion{ID: "deletion_1", RequestedBy: "usr_1", RequestedAt: testTime(), EarliestExecutionAt: testTime()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandRequestDeletion, ActorID: "usr_1", Deletion: &deletion, At: testTime()})

	encoded, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	var restored Project
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Version != project.Version || restored.Deletion == nil || restored.Deletion.Status != ProjectDeletionBlocked || len(restored.LegalHolds) != 1 || restored.LegalHolds[0].ReleasedAt != nil {
		t.Fatalf("durable lifecycle round trip lost legal hold or deletion state: %#v", restored)
	}

	restored = applyProject(t, restored, ProjectCommand{Type: ProjectCommandReleaseLegalHold, ActorID: "compliance_2", LegalHoldID: hold.ID, ReleaseReason: "request completed", At: testTime()})
	restored = applyProject(t, restored, ProjectCommand{Type: ProjectCommandBeginDeletion, ActorID: "svc_retention", At: testTime()})
	if restored.Deletion == nil || restored.Deletion.Status != ProjectDeletionErasing || restored.LegalHolds[0].ReleasedAt == nil {
		t.Fatalf("restored lifecycle could not continue safely: %#v", restored)
	}
}

func TestProjectDeletionCompletionKeepsOnlyContentFreeLifecycleIndex(t *testing.T) {
	project := createProject(t)
	project.DeploymentTargets = []string{"production"}
	project.PromptBundleVersion = "1.0.0"
	deletion := ProjectDeletion{ID: "deletion_1", RequestedBy: "usr_1", RequestedAt: testTime(), EarliestExecutionAt: testTime()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandRequestDeletion, ActorID: "usr_1", Deletion: &deletion, At: testTime()})
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandBeginDeletion, ActorID: "svc_retention", At: testTime()})
	backupExpiry := testTime().Add(35 * 24 * time.Hour)
	proof := ProjectDeletion{ProofSHA256: digestOne(), ProofArtifactURI: "artifact://sha256/" + digestOne()[len("sha256:"):], BackupExpiresAt: &backupExpiry}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandCompleteDeletion, ActorID: "svc_retention", Deletion: &proof, At: testTime()})
	if project.State != contracts.ProjectArchived || project.Deletion.Status != ProjectDeletionCompleted || project.Deletion.CompletedAt == nil || project.Deletion.ProofSHA256 != digestOne() {
		t.Fatalf("completed deletion = %#v", project)
	}
	if project.Goal != nil || project.Plan != nil || len(project.DeploymentTargets) != 0 || project.PromptBundleVersion != "" || project.PausedFromState != "" {
		t.Fatalf("online projection retained project content: %#v", project)
	}
}

func TestProjectDeletionCannotBeginBeforeRetentionDeadline(t *testing.T) {
	project := createProject(t)
	deletion := ProjectDeletion{ID: "deletion_1", RequestedBy: "usr_1", RequestedAt: testTime(), EarliestExecutionAt: testTime().Add(time.Hour)}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandRequestDeletion, ActorID: "usr_1", Deletion: &deletion, At: testTime()})
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandBeginDeletion, ActorID: "svc_retention", At: testTime()}); err == nil || err.Code != aorerrors.CodeInvalidStateTransition {
		t.Fatalf("early deletion = %#v", err)
	}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandBeginDeletion, ActorID: "svc_retention", At: testTime().Add(time.Hour)})
	if project.Deletion.Status != ProjectDeletionErasing {
		t.Fatalf("eligible deletion = %#v", project.Deletion)
	}
}

func TestOneHundredGoalRoundsNeverAutoApproveOrPlan(t *testing.T) {
	project := createProject(t)
	for version := 1; version <= 100; version++ {
		goal := GoalRecord{ID: "goal_1", Version: version, SHA256: digestZero(), UnresolvedItems: []string{"user decision"}}
		project = applyProject(t, project, ProjectCommand{Type: ProjectCommandProposeGoal, Goal: &goal, ActorID: "agt_goal", At: testTime()})
	}
	if project.State != contracts.ProjectGoalNegotiating || project.Goal.Version != 100 || project.Goal.ApprovedBy != "" || project.Plan != nil {
		t.Fatalf("negotiation auto-progressed: %#v", project)
	}
}

func TestPauseAndResumePreserveGoalOrExecutionPhase(t *testing.T) {
	project := createProject(t)
	paused := applyProject(t, project, ProjectCommand{Type: ProjectCommandPause, ActorID: "usr_1", At: testTime()})
	if paused.State != contracts.ProjectGoalSuspended || paused.PausedFromState != contracts.ProjectGoalNegotiating {
		t.Fatalf("goal pause = %#v", paused)
	}
	resumed := applyProject(t, paused, ProjectCommand{Type: ProjectCommandResume, ActorID: "usr_1", At: testTime()})
	if resumed.State != contracts.ProjectGoalNegotiating || resumed.PausedFromState != "" {
		t.Fatalf("goal resume = %#v", resumed)
	}
	resumed = applyProject(t, resumed, ProjectCommand{Type: ProjectCommandPause, ActorID: "usr_1", At: testTime()})
	if resumed.State != contracts.ProjectGoalSuspended {
		t.Fatalf("second goal pause = %#v", resumed)
	}
}

func TestProjectExecutionGatesRequireVerifiedFacts(t *testing.T) {
	project := createProject(t)
	goal := GoalRecord{ID: "goal_1", Version: 1, SHA256: digestZero()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandProposeGoal, Goal: &goal, ActorID: "agt_goal", At: testTime()})
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandApproveGoal, Goal: &goal, ActorID: "usr_1", Approval: goalApproval(goal, "usr_1"), At: testTime()})
	plan := contracts.SpecRef{Version: 1, SHA256: digestZero()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandPublishPlan, GoalSpecRef: &plan, Plan: &plan, DAG: map[string][]string{"task_1": {}}, ActorID: "agt_plan", At: testTime()})
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandBeginIntegration, ActorID: "svc_orchestrator", At: testTime()}); err == nil {
		t.Fatal("integration started without guard facts")
	}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandBeginIntegration, ActorID: "svc_orchestrator", Guard: &ProjectGuardFacts{AllTasksPassed: true, EvidenceSHA256: digestZero()}, At: testTime()})
	if _, err := DecideProject(project, ProjectCommand{Type: ProjectCommandBeginGlobalAudit, ActorID: "svc_orchestrator", Guard: &ProjectGuardFacts{AllTasksIntegrated: true, EvidenceSHA256: digestZero()}, At: testTime()}); err == nil {
		t.Fatal("global audit started without integration audit result")
	}
}

func createProject(t *testing.T) Project {
	t.Helper()
	event, err := DecideProject(Project{}, ProjectCommand{Type: ProjectCommandCreate, TenantID: "tenant_1", ProjectID: "prj_1", ActorID: "usr_1", GoalAgentCount: 2, At: testTime()})
	if err != nil {
		t.Fatal(err)
	}
	project, applyErr := ApplyProject(Project{}, event)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	return applyProject(t, project, ProjectCommand{Type: ProjectCommandStartGoalNegotiation, ActorID: "svc_orchestrator", At: testTime()})
}

func applyProject(t *testing.T, current Project, command ProjectCommand) Project {
	t.Helper()
	event, err := DecideProject(current, command)
	if err != nil {
		t.Fatal(err)
	}
	next, applyErr := ApplyProject(current, event)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	return next
}

func testTime() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}

func digestZero() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func digestOne() string {
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}

func goalApproval(goal GoalRecord, principalID string) *ApprovalBinding {
	return &ApprovalBinding{
		RecordID: "approval_1", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: goal.ID,
		SubjectVersion: goal.Version, SubjectSHA256: goal.SHA256, PrincipalID: principalID, Reason: "explicit test approval",
		IssuedAt: testTime(), Signature: "test-signature",
	}
}
