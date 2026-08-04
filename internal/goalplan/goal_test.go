package goalplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type scriptedGoalInvoker struct {
	invocations []AgentInvocation
	unresolved  bool
}

type goalPlanCommitBoundary struct{}

type principalRecordingCommander struct {
	delegate  ProjectCommander
	handled   []string
	published []string
}

func (commander *principalRecordingCommander) HandleProject(ctx context.Context, request orchestrator.ProjectRequest) (orchestrator.ProjectOutcome, error) {
	commander.handled = append(commander.handled, request.PrincipalID)
	return commander.delegate.HandleProject(ctx, request)
}

func (commander *principalRecordingCommander) HandleTask(ctx context.Context, request orchestrator.TaskRequest) (orchestrator.TaskOutcome, error) {
	return commander.delegate.HandleTask(ctx, request)
}

func (commander *principalRecordingCommander) QueuePlanTasks(ctx context.Context, request orchestrator.QueuePlanTasksRequest) (orchestrator.QueuePlanTasksOutcome, error) {
	return commander.delegate.QueuePlanTasks(ctx, request)
}

func (commander *principalRecordingCommander) PublishPlan(ctx context.Context, request orchestrator.PublishPlanRequest) (orchestrator.PublishPlanOutcome, error) {
	commander.published = append(commander.published, request.PrincipalID)
	return commander.delegate.PublishPlan(ctx, request)
}

func (commander *principalRecordingCommander) Project(ctx context.Context, tenantID, projectID string) (state.Project, bool, error) {
	return commander.delegate.Project(ctx, tenantID, projectID)
}

func (goalPlanCommitBoundary) Validate(_ context.Context, validation orchestrator.CommitValidation) error {
	if validation.TenantID == "" || validation.ProjectID == "" || validation.PrincipalID == "" || validation.Action == "" || validation.ParameterDigest == "" || validation.CommitAt.IsZero() {
		return orchestrator.ErrCommitBoundary
	}
	return nil
}

func (i *scriptedGoalInvoker) Invoke(_ context.Context, invocation AgentInvocation) (AgentRecord, error) {
	i.invocations = append(i.invocations, invocation)
	switch invocation.Role {
	case agentruntime.RoleGoalProposer:
		content := validGoalContent("Goal " + fmt.Sprint(len(i.invocations)))
		if i.unresolved {
			content.UnresolvedItems = []string{"user decision required"}
		}
		payload, _ := json.Marshal(content)
		return AgentRecord{RunID: invocation.InvocationID, AgentInstanceID: "agt_proposer", Role: invocation.Role, Payload: payload}, nil
	case agentruntime.RoleGoalChallenger:
		payload := json.RawMessage(`{"findings":[{"severity":"HIGH","affectedClause":"acceptance","evidence":"criterion is ambiguous","question":"Which latency percentile is required?"}]}`)
		return AgentRecord{RunID: invocation.InvocationID, AgentInstanceID: "agt_challenger", Role: invocation.Role, Payload: payload}, nil
	default:
		return AgentRecord{}, ErrAgentOutput
	}
}

func TestSingleAgentNegotiationRunsHundredRoundsWithoutApproval(t *testing.T) {
	negotiator, invoker, service := negotiationHarness(t, 1)
	var previous *contracts.SpecRef
	for round := 1; round <= 100; round++ {
		result, err := negotiator.Negotiate(context.Background(), NegotiationRequest{
			TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: fmt.Sprintf("msg_%03d", round),
			UserPrincipalID: "usr_1", UserInput: []byte(fmt.Sprintf("round %d", round)), GoalAgentCount: 1,
			PreviousRef: previous, ExpectedProjectVersion: int64(round + 1), IdempotencyKey: fmt.Sprintf("goal_%03d", round),
		})
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if result.Goal.Content.Version != round || result.Goal.Status != contracts.GoalDraft || result.Project.Project.State != contracts.ProjectGoalNegotiating || result.Project.Project.Plan != nil {
			t.Fatalf("round %d result = %#v", round, result)
		}
		ref := contracts.SpecRef{Version: result.Goal.Content.Version, SHA256: result.Goal.ContentSHA256}
		previous = &ref
	}
	project, found, err := service.Project(context.Background(), "tenant_1", "prj_1")
	if err != nil || !found || project.Goal == nil || project.Goal.Version != 100 || project.State != contracts.ProjectGoalNegotiating || project.Plan != nil {
		t.Fatalf("project = %#v found %v err %v", project, found, err)
	}
	if len(invoker.invocations) != 100 {
		t.Fatalf("invocations = %d", len(invoker.invocations))
	}
	messages, err := service.GoalMessages(context.Background(), "tenant_1", "prj_1")
	if err != nil {
		t.Fatalf("goal messages: %v", err)
	}
	if len(messages) != 100 {
		t.Fatalf("goal message count = %d", len(messages))
	}
	seen := make(map[string]bool, len(messages))
	for _, message := range messages {
		seen[message.Message] = true
	}
	if !seen["round 1"] || !seen["round 100"] {
		t.Fatalf("missing boundary rounds: round 1=%t round 100=%t", seen["round 1"], seen["round 100"])
	}
}

func TestNegotiatorCommitsAgentDraftAsAuthenticatedUser(t *testing.T) {
	negotiator, _, _ := negotiationHarness(t, 1)
	commander := &principalRecordingCommander{delegate: negotiator.projects}
	negotiator.projects = commander
	_, err := negotiator.Negotiate(context.Background(), NegotiationRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: "msg_1", UserPrincipalID: "usr_1",
		UserInput: []byte("build"), GoalAgentCount: 1, ExpectedProjectVersion: 2, IdempotencyKey: "draft",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(commander.handled) != 1 || commander.handled[0] != "usr_1" {
		t.Fatalf("goal commit principals = %#v", commander.handled)
	}
}

func TestDualAgentNegotiationPersistsIndependentChallengeAndRequiresUserApproval(t *testing.T) {
	negotiator, invoker, service := negotiationHarness(t, 2)
	request := NegotiationRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: "msg_1", UserPrincipalID: "usr_1",
		UserInput: []byte("build a service"), GoalAgentCount: 2, ExpectedProjectVersion: 2, IdempotencyKey: "goal_round_1",
	}
	result, err := negotiator.Negotiate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Goal.Content.Version != 2 || result.Challenge == nil || result.Challenge.GoalSpecRef.Version != 1 || result.ChallengeArtifact == nil || len(invoker.invocations) != 3 {
		t.Fatalf("dual result = %#v calls=%d", result, len(invoker.invocations))
	}
	if invoker.invocations[0].Role != agentruntime.RoleGoalProposer || invoker.invocations[1].Role != agentruntime.RoleGoalChallenger || invoker.invocations[2].Role != agentruntime.RoleGoalProposer {
		t.Fatalf("role order = %#v", invoker.invocations)
	}
	replayed, err := negotiator.Negotiate(context.Background(), request)
	if err != nil || !replayed.Project.Duplicate || len(invoker.invocations) != 3 {
		t.Fatalf("replay = %#v err=%v calls=%d", replayed.Project, err, len(invoker.invocations))
	}
	project, _, _ := service.Project(context.Background(), "tenant_1", "prj_1")
	if project.State != contracts.ProjectGoalNegotiating || project.Plan != nil {
		t.Fatalf("project advanced without approval = %#v", project)
	}
	ref := contracts.SpecRef{Version: result.Goal.Content.Version, SHA256: result.Goal.ContentSHA256}
	approved, err := negotiator.Approve(context.Background(), ApprovalRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", GoalRef: ref, UserPrincipalID: "usr_1",
		ExpectedProjectVersion: 3, IdempotencyKey: "approve_goal", Approval: validGoalApproval(ref),
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved.Project.State != contracts.ProjectPlanning || approved.Project.Goal.ApprovedBy != "usr_1" {
		t.Fatalf("approved project = %#v", approved.Project)
	}
	if _, found, err := negotiator.artifacts.Get(context.Background(), "tenant_1", "prj_1", ArtifactGoalApproved, "goal_1", ref.Version); err != nil || !found {
		t.Fatalf("approved artifact = found %v err %v", found, err)
	}
}

func TestApprovalRejectsUnresolvedGoalBeforeStateChange(t *testing.T) {
	negotiator, invoker, service := negotiationHarness(t, 1)
	invoker.unresolved = true
	result, err := negotiator.Negotiate(context.Background(), NegotiationRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: "msg_1", UserPrincipalID: "usr_1",
		UserInput: []byte("ambiguous request"), GoalAgentCount: 1, ExpectedProjectVersion: 2, IdempotencyKey: "draft_goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := contracts.SpecRef{Version: result.Goal.Content.Version, SHA256: result.Goal.ContentSHA256}
	_, err = negotiator.Approve(context.Background(), ApprovalRequest{TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", GoalRef: ref, UserPrincipalID: "usr_1", ExpectedProjectVersion: 3, IdempotencyKey: "approve", Approval: validGoalApproval(ref)})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("approval = %v", err)
	}
	project, _, _ := service.Project(context.Background(), "tenant_1", "prj_1")
	if project.State != contracts.ProjectGoalNegotiating || project.Goal.ApprovedBy != "" {
		t.Fatalf("project changed = %#v", project)
	}
}

func negotiationHarness(t *testing.T, agentCount int) (*Negotiator, *scriptedGoalInvoker, *orchestrator.Service) {
	t.Helper()
	events := eventing.NewMemoryStore()
	service := orchestrator.NewWithBoundary(events, goalPlanClock, goalPlanCommitBoundary{})
	requests := []orchestrator.ProjectRequest{
		{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "create", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: agentCount}},
		{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "start", ExpectedVersion: 1, Command: state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}},
	}
	for _, request := range requests {
		if _, err := service.HandleProject(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	artifacts, err := NewEventArtifactStore(events, goalPlanClock)
	if err != nil {
		t.Fatal(err)
	}
	invoker := &scriptedGoalInvoker{}
	negotiator, err := NewNegotiator(artifacts, invoker, service, goalPlanClock)
	if err != nil {
		t.Fatal(err)
	}
	return negotiator, invoker, service
}

func validGoalContent(title string) contracts.GoalContent {
	return contracts.GoalContent{
		GoalSpecVersion: 1, Title: title, Summary: "summary", ProblemStatement: "problem",
		BusinessOutcomes: []contracts.Outcome{{ID: "outcome_1", Statement: "measurable outcome"}},
		Scope:            contracts.Scope{Included: []string{"service"}, Excluded: []string{}}, UserPersonas: []string{"operator"},
		FunctionalRequirements:    []string{"serve requests"},
		NonFunctionalRequirements: contracts.NonFunctionalRequirements{Security: []string{}, Privacy: []string{}, Performance: []string{}, Reliability: []string{}, Operability: []string{}},
		Constraints:               []string{}, Assumptions: []contracts.Assumption{}, Decisions: []string{}, UnresolvedItems: []string{},
		AcceptanceCriteria: []contracts.AcceptanceCriterion{{ID: "criterion_1", Statement: "tests pass", EvidenceType: "AUTOMATED"}},
		RiskTolerance:      contracts.RiskLow, HumanApprovalPoints: []string{"goal"}, DataClassification: contracts.DataInternal,
		DeploymentTargets: []string{"linux"}, SourceReferences: []string{},
	}
}

func validGoalApproval(ref contracts.SpecRef) ApprovalBinding {
	return ApprovalBinding{RecordID: "approval_goal", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: "goal_1", SubjectVersion: ref.Version, SubjectSHA256: ref.SHA256, PrincipalID: "usr_1", Reason: "goal is correct", IssuedAt: goalPlanClock(), Signature: "signed-approval"}
}
