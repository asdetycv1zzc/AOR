package state

import (
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

func TestProjectCannotCompleteWithoutReleaseApprovalAndEvidence(t *testing.T) {
	project := Project{TenantID: "tenant_1", ID: "prj_1", State: contracts.ProjectGlobalAudit, Version: 8}
	_, err := DecideProject(project, ProjectCommand{Type: ProjectCommandComplete, ActorID: "svc_orchestrator", Completion: &CompletionFacts{AllTasksIntegrated: true, GoalCriteriaSatisfied: true, GlobalAuditPassed: true, ReleaseArtifactsSigned: true, NoBlockingFindings: true, EvidenceSHA256: digestZero()}, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeInvalidStateTransition {
		t.Fatalf("unsigned completion = %#v", err)
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
