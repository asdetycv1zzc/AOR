package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

func TestGoalMessageIsImmutableAuditedAndIdempotent(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	createGoalProject(t, service, false)
	request := ProjectRequest{
		TenantID: "tenant_1", ProjectID: "prj_goal", PrincipalID: "usr_1", IdempotencyKey: "goal-message-1", ExpectedVersion: 1,
		Command: state.ProjectCommand{Type: state.ProjectCommandSubmitGoalMessage, GoalMessage: &state.GoalMessage{Message: "build the service"}},
	}
	first, err := service.HandleProject(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Project.State != contracts.ProjectGoalNegotiating || first.Project.Version != 2 || len(first.Events) != 2 {
		t.Fatalf("first outcome = %#v", first)
	}
	messages, err := service.GoalMessages(context.Background(), "tenant_1", "prj_goal")
	if err != nil || len(messages) != 1 || messages[0].Message != "build the service" || messages[0].CreatedBy != "usr_1" || messages[0].Kind != state.GoalMessageUser {
		t.Fatalf("messages = %#v error=%v", messages, err)
	}
	requireRecordUUIDv7(t, messages[0].ID)
	second, err := service.HandleProject(context.Background(), request)
	if err != nil || !second.Duplicate || second.Project.Version != 2 {
		t.Fatalf("duplicate outcome = %#v error=%v", second, err)
	}
	changed := request
	changed.Command.GoalMessage = &state.GoalMessage{Message: "different request"}
	_, err = service.HandleProject(context.Background(), changed)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed duplicate = %#v", err)
	}
	if stats := store.Stats(); stats.Projections != 2 || stats.Events != 3 || stats.Outbox != 3 || stats.CommandResults != 2 {
		t.Fatalf("store stats = %#v", stats)
	}
}

func TestGoalSpecLifecyclePersistsStatusApprovalAndChangeMessageAtomically(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := newTestService(store)
	createGoalProject(t, service, true)
	draft := testGoalSpec(t, "prj_goal", 1, nil)
	goal := state.GoalRecord{ID: "goal_1", Version: 1, SHA256: draft.ContentSHA256}
	proposed, err := service.HandleProject(context.Background(), ProjectRequest{
		TenantID: "tenant_1", ProjectID: "prj_goal", PrincipalID: "agt_goal", IdempotencyKey: "propose-goal", ExpectedVersion: 2,
		Command: state.ProjectCommand{Type: state.ProjectCommandProposeGoal, Goal: &goal, GoalSpec: &draft},
	})
	if err != nil || proposed.Project.Version != 3 || proposed.Project.Goal.Status != contracts.GoalDraft {
		t.Fatalf("proposed = %#v error=%v", proposed, err)
	}
	stored, found, err := service.GoalSpec(context.Background(), "tenant_1", "prj_goal", 1)
	if err != nil || !found || stored.Spec.Status != contracts.GoalDraft || stored.Revision != 1 {
		t.Fatalf("stored draft = %#v found=%t error=%v", stored, found, err)
	}
	requireRecordUUIDv7(t, stored.RecordID)
	approval := &state.ApprovalBinding{
		RecordID: "approval_1", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: goal.ID,
		SubjectVersion: goal.Version, SubjectSHA256: goal.SHA256, PrincipalID: "usr_1", Reason: "explicit approval", IssuedAt: fixedClock(), Signature: "authenticated",
	}
	approvalRequest := ProjectRequest{
		TenantID: "tenant_1", ProjectID: "prj_goal", PrincipalID: "usr_1", IdempotencyKey: "approve-goal", ExpectedVersion: 3,
		Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: &goal, Approval: approval},
	}
	approved, err := service.HandleProject(context.Background(), approvalRequest)
	if err != nil || approved.Project.Version != 4 || approved.Project.Goal.Status != contracts.GoalApproved {
		t.Fatalf("approved = %#v error=%v", approved, err)
	}
	requireRecordUUIDv7(t, approved.Project.Goal.ApprovalRecordID)
	if approved.Project.Goal.ApprovalRecordID == approval.RecordID {
		t.Fatal("orchestrator trusted a caller-derived approval primary key")
	}
	replayedApproval, err := service.HandleProject(context.Background(), approvalRequest)
	if err != nil || !replayedApproval.Duplicate || replayedApproval.Project.Goal.ApprovalRecordID != approved.Project.Goal.ApprovalRecordID {
		t.Fatalf("replayed approval = %#v error=%v", replayedApproval, err)
	}
	stored, found, err = service.GoalSpec(context.Background(), "tenant_1", "prj_goal", 1)
	if err != nil || !found || stored.Spec.Status != contracts.GoalApproved || stored.Spec.ApprovedBy == nil || stored.Spec.ApprovedBy.ActorID != "usr_1" || stored.Revision != 2 {
		t.Fatalf("stored approval = %#v found=%t error=%v", stored, found, err)
	}
	changed, err := service.HandleProject(context.Background(), ProjectRequest{
		TenantID: "tenant_1", ProjectID: "prj_goal", PrincipalID: "usr_1", IdempotencyKey: "change-goal", ExpectedVersion: 4,
		Command: state.ProjectCommand{Type: state.ProjectCommandRequestGoalChange, Goal: &goal, GoalMessage: &state.GoalMessage{Message: "add a deployment target"}},
	})
	if err != nil || changed.Project.Version != 5 || changed.Project.State != contracts.ProjectGoalNegotiating || changed.Project.Goal.Status != contracts.GoalSuperseded || len(changed.Events) != 3 {
		t.Fatalf("changed = %#v error=%v", changed, err)
	}
	stored, found, err = service.GoalSpec(context.Background(), "tenant_1", "prj_goal", 1)
	if err != nil || !found || stored.Spec.Status != contracts.GoalSuperseded || stored.Spec.ApprovedBy != nil || stored.Revision != 3 {
		t.Fatalf("stored superseded = %#v found=%t error=%v", stored, found, err)
	}
	messages, err := service.GoalMessages(context.Background(), "tenant_1", "prj_goal")
	if err != nil || len(messages) != 1 || messages[0].Kind != state.GoalMessageChangeRequest {
		t.Fatalf("change messages = %#v error=%v", messages, err)
	}
	if stats := store.Stats(); stats.Approvals != 1 || stats.Events != stats.Outbox {
		t.Fatalf("store stats = %#v", stats)
	}
}

func createGoalProject(t *testing.T, service *Service, start bool) {
	t.Helper()
	if _, err := service.HandleProject(context.Background(), ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_goal", PrincipalID: "usr_1", IdempotencyKey: "create-goal-project", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 1}}); err != nil {
		t.Fatal(err)
	}
	if start {
		if _, err := service.HandleProject(context.Background(), ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_goal", PrincipalID: "usr_1", IdempotencyKey: "start-goal-project", ExpectedVersion: 1, Command: state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}}); err != nil {
			t.Fatal(err)
		}
	}
}

func testGoalSpec(t *testing.T, projectID string, version int, unresolved []string) contracts.GoalSpec {
	t.Helper()
	content := contracts.GoalContent{
		GoalSpecVersion: 1, ProjectID: projectID, Version: version, Title: "Goal", Summary: "Summary", ProblemStatement: "Problem",
		BusinessOutcomes: []contracts.Outcome{{ID: "outcome_1", Statement: "Outcome"}}, Scope: contracts.Scope{Included: []string{"service"}, Excluded: []string{}},
		UserPersonas: []string{}, FunctionalRequirements: []string{"serve requests"},
		NonFunctionalRequirements: contracts.NonFunctionalRequirements{Security: []string{}, Privacy: []string{}, Performance: []string{}, Reliability: []string{}, Operability: []string{}},
		Constraints:               []string{}, Assumptions: []contracts.Assumption{}, Decisions: []string{}, UnresolvedItems: append([]string(nil), unresolved...),
		AcceptanceCriteria: []contracts.AcceptanceCriterion{{ID: "criterion_1", Statement: "passes", EvidenceType: "AUTOMATED"}},
		RiskTolerance:      contracts.RiskLow, HumanApprovalPoints: []string{}, DataClassification: contracts.DataInternal, DeploymentTargets: []string{"test"}, SourceReferences: []string{},
		CreatedAt: fixedClock().Format("2006-01-02T15:04:05Z07:00"), CreatedBy: contracts.AgentIdentity{AgentInstanceID: "agt_goal", Role: "GOAL_PROPOSER"},
	}
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.GoalSpec{Content: content, Status: contracts.GoalDraft, ContentSHA256: digest}
}

func requireRecordUUIDv7(t *testing.T, value string) {
	t.Helper()
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.Version() != uuid.Version(7) {
		t.Fatalf("record id %q is not UUIDv7", value)
	}
}
