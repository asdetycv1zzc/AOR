package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

type recordingGoalNegotiator struct {
	negotiationRequest goalplan.NegotiationRequest
	approvalRequest    goalplan.ApprovalRequest
	negotiationResult  goalplan.NegotiationResult
	approvalResult     orchestrator.ProjectOutcome
	negotiationErr     error
	approvalErr        error
	calls              *[]string
}

func (service *recordingGoalNegotiator) Negotiate(_ context.Context, request goalplan.NegotiationRequest) (goalplan.NegotiationResult, error) {
	service.negotiationRequest = request
	if service.calls != nil {
		*service.calls = append(*service.calls, "negotiate")
	}
	result := service.negotiationResult
	if result.Artifact.SpecID == "" {
		result.Artifact.SpecID = request.GoalSpecID
	}
	if result.Project.Project.Goal != nil && result.Project.Project.Goal.ID == "" {
		result.Project.Project.Goal.ID = request.GoalSpecID
	}
	return result, service.negotiationErr
}

func (service *recordingGoalNegotiator) Approve(_ context.Context, request goalplan.ApprovalRequest) (orchestrator.ProjectOutcome, error) {
	service.approvalRequest = request
	if service.calls != nil {
		*service.calls = append(*service.calls, "approve")
	}
	return service.approvalResult, service.approvalErr
}

type recordingGoalPlanner struct {
	request goalplan.PlanningRequest
	result  goalplan.PlanningResult
	err     error
	calls   *[]string
}

func (service *recordingGoalPlanner) BuildAndPublishAutomatic(_ context.Context, request goalplan.PlanningRequest) (goalplan.PlanningResult, error) {
	service.request = request
	if service.calls != nil {
		*service.calls = append(*service.calls, "plan")
	}
	result := service.result
	if result.PlanArtifact.SpecID == "" {
		result.PlanArtifact.SpecID = request.PlanSpecID
	}
	return result, service.err
}

func TestConfiguredGoalPlanServicesReplaceLegacyMessageOnlyPath(t *testing.T) {
	negotiator := &recordingGoalNegotiator{}
	planner := &recordingGoalPlanner{}
	handler, _, authorizer := newGoalPlanTestHandler(t, negotiator, planner)
	project := createTestProject(t, handler)
	goal := controlGoalSpec(t, project.ID, 1, nil)
	negotiator.negotiationResult = goalplan.NegotiationResult{
		Goal: goal,
		Artifact: goalplan.SpecArtifact{
			TenantID: testTenantID, ProjectID: project.ID, Kind: goalplan.ArtifactGoalDraft,
			Version: 1, ContentSHA256: goal.ContentSHA256,
		},
		Project: orchestrator.ProjectOutcome{Project: state.Project{
			TenantID: testTenantID, ID: project.ID, Version: 2, State: contracts.ProjectGoalNegotiating,
			Goal: &state.GoalRecord{Version: 1, SHA256: goal.ContentSHA256},
		}},
	}
	body := []byte(`{"expectedVersion":1,"message":"build through the goal runtime"}`)
	response := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/goal/messages", body, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "goal-runtime-1", "If-Match": `"v1"`,
	})
	if response.Code != http.StatusAccepted || response.Header().Get("ETag") != `"v2"` || !strings.Contains(response.Body.String(), `"goal"`) {
		t.Fatalf("response status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	request := negotiator.negotiationRequest
	goalSpecID := request.GoalSpecID
	requireGoalPlanUUIDv7(t, goalSpecID)
	requireGoalPlanUUIDv7(t, request.MessageID)
	if request.TenantID != testTenantID || request.ProjectID != project.ID || request.GoalSpecID != goalSpecID || request.UserPrincipalID != "user-1" || string(request.UserInput) != "build through the goal runtime" || request.GoalAgentCount != 1 || request.PreviousRef != nil || request.SupersedeApprovedGoal || request.ExpectedProjectVersion != 1 || request.MessageID == "" || request.IdempotencyKey == "goal-runtime-1" || len(request.IdempotencyKey) > 256 {
		t.Fatalf("negotiation request = %#v", request)
	}
	if last := authorizer.inputs[len(authorizer.inputs)-1]; last.Action != "project.command" || last.Resource.Type != "project" || last.Resource.ID != project.ID {
		t.Fatalf("workflow authorization = %#v", last)
	}
}

func TestConfiguredGoalNegotiationRetryUsesOriginalGoalContext(t *testing.T) {
	negotiator := &recordingGoalNegotiator{}
	handler, _, _ := newGoalPlanTestHandler(t, negotiator, &recordingGoalPlanner{})
	project := createTestProject(t, handler)
	goal := controlGoalSpec(t, project.ID, 1, nil)
	seedGoalSpec(t, handler, project.ID, 1, state.ProjectCommandProposeGoal, goal)
	current, found, err := handler.orchestrator.Project(context.Background(), testTenantID, project.ID)
	if err != nil || !found {
		t.Fatalf("load project: found=%t error=%v", found, err)
	}
	negotiator.negotiationResult = goalplan.NegotiationResult{
		Goal: goal,
		Artifact: goalplan.SpecArtifact{
			TenantID: testTenantID, ProjectID: project.ID, Kind: goalplan.ArtifactGoalDraft,
			SpecID: current.Goal.ID, Version: 1, ContentSHA256: goal.ContentSHA256,
		},
		Project: orchestrator.ProjectOutcome{Project: current},
	}
	principal := authn.Principal{ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID}
	if _, err := handler.negotiateGoal(context.Background(), principal, project.ID, goalMessageBody{ExpectedVersion: 1, Message: "build through the goal runtime"}, "goal-runtime-retry"); err != nil {
		t.Fatal(err)
	}
	request := negotiator.negotiationRequest
	if request.GoalSpecID != current.Goal.ID || request.PreviousRef != nil || request.SupersedeApprovedGoal {
		t.Fatalf("retry negotiation request = %#v", request)
	}
}

func TestConfiguredGoalApprovalSynchronouslyPublishesInitialPlan(t *testing.T) {
	calls := []string{}
	negotiator := &recordingGoalNegotiator{calls: &calls}
	planner := &recordingGoalPlanner{calls: &calls}
	handler, store, _ := newGoalPlanTestHandler(t, negotiator, planner)
	project := createTestProject(t, handler)
	draft := controlGoalSpec(t, project.ID, 1, nil)
	seedGoalSpec(t, handler, project.ID, 1, state.ProjectCommandProposeGoal, draft)
	goalSpecID := "22222222-2222-4222-8222-222222222222"
	approvedProject := state.Project{
		TenantID: testTenantID, ID: project.ID, Version: 3, State: contracts.ProjectPlanning,
		Goal: &state.GoalRecord{ID: goalSpecID, Version: 1, SHA256: draft.ContentSHA256, ApprovedBy: "user-1"},
	}
	negotiator.approvalResult = orchestrator.ProjectOutcome{Project: approvedProject}
	plan := contracts.PlanSpec{PlanSpecVersion: 1, ProjectID: project.ID, GoalSpecRef: contracts.SpecRef{Version: 1, SHA256: draft.ContentSHA256}, SHA256: "sha256:" + strings.Repeat("3", 64)}
	planContent, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := goalplan.NewEventArtifactStore(store, func() time.Time { return controlAPITestTime })
	if err != nil {
		t.Fatal(err)
	}
	storedPlanID := uuid.Must(uuid.NewV7()).String()
	if _, err := artifacts.Put(context.Background(), goalplan.SpecArtifact{
		TenantID: testTenantID, ProjectID: project.ID, Kind: goalplan.ArtifactPlanSpec, SpecID: storedPlanID,
		Version: 1, ContentSHA256: plan.SHA256, Content: planContent, CreatedBy: "agt_plan",
	}); err != nil {
		t.Fatal(err)
	}
	executingProject := approvedProject
	executingProject.Version = 4
	executingProject.State = contracts.ProjectExecuting
	executingProject.Plan = &contracts.SpecRef{Version: 1, SHA256: plan.SHA256}
	planner.result = goalplan.PlanningResult{
		Plan: plan,
		PlanArtifact: goalplan.SpecArtifact{
			TenantID: testTenantID, ProjectID: project.ID, Kind: goalplan.ArtifactPlanSpec,
			Version: 1, ContentSHA256: plan.SHA256,
		},
		Publication: orchestrator.PublishPlanOutcome{Project: executingProject},
	}
	body := []byte(`{"expectedVersion":2,"sha256":"` + draft.ContentSHA256 + `","decision":"APPROVE","comment":"requirements are correct","idempotencyKey":"approve-runtime-1"}`)
	response := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/goal/specs/1:approve", body, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "approve-runtime-1", "If-Match": `"v2"`,
	})
	if response.Code != http.StatusAccepted || response.Header().Get("ETag") != `"v4"` || !strings.Contains(response.Body.String(), `"state":"EXECUTING"`) {
		t.Fatalf("response status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	if strings.Join(calls, ",") != "approve,plan" {
		t.Fatalf("calls = %v", calls)
	}
	approval := negotiator.approvalRequest
	requireGoalPlanUUIDv7(t, approval.Approval.RecordID)
	if approval.GoalSpecID != goalSpecID || approval.GoalRef != (contracts.SpecRef{Version: 1, SHA256: draft.ContentSHA256}) || approval.UserPrincipalID != "user-1" || approval.ExpectedProjectVersion != 2 || approval.IdempotencyKey != "approve-runtime-1" || approval.Approval.RecordID == "" || approval.Approval.PrincipalID != "user-1" || approval.Approval.SubjectID != goalSpecID || approval.Approval.IssuedAt != controlAPITestTime {
		t.Fatalf("approval request = %#v", approval)
	}
	planning := planner.request
	requireGoalPlanUUIDv7(t, planning.PlanSpecID)
	if planning.TenantID != testTenantID || planning.ProjectID != project.ID || planning.PrincipalID != "user-1" || planning.GoalSpecID != goalSpecID || planning.GoalRef != approval.GoalRef || planning.PlanSpecID != storedPlanID || planning.PlanVersion != 1 || planning.ExpectedProjectVersion != 3 || planning.IdempotencyKey == "approve-runtime-1" || len(planning.ModuleTaskIDs) != 0 || len(planning.AttemptSeriesIDs) != 0 || len(planning.ModuleSpecVersions) != 0 || len(planning.RetainedModules) != 0 {
		t.Fatalf("planning request = %#v", planning)
	}
}

func TestConfiguredGoalApprovalFailsClosedWhenPlanningRuntimeIsUnavailable(t *testing.T) {
	calls := []string{}
	negotiator := &recordingGoalNegotiator{calls: &calls}
	planner := &recordingGoalPlanner{calls: &calls, err: modelgateway.ErrProviderUnavailable}
	handler, _, _ := newGoalPlanTestHandler(t, negotiator, planner)
	project := createTestProject(t, handler)
	draft := controlGoalSpec(t, project.ID, 1, nil)
	seedGoalSpec(t, handler, project.ID, 1, state.ProjectCommandProposeGoal, draft)
	negotiator.approvalResult = orchestrator.ProjectOutcome{Project: state.Project{
		TenantID: testTenantID, ID: project.ID, Version: 3, State: contracts.ProjectPlanning,
		Goal: &state.GoalRecord{ID: "22222222-2222-4222-8222-222222222222", Version: 1, SHA256: draft.ContentSHA256, ApprovedBy: "user-1"},
	}}
	body := []byte(`{"expectedVersion":2,"sha256":"` + draft.ContentSHA256 + `"}`)
	response := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/goal/specs/1:approve", body, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "approve-runtime-down", "If-Match": `"v2"`,
	})
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "AOR_DEPENDENCY_UNAVAILABLE") || strings.Contains(response.Body.String(), `"state":"EXECUTING"`) {
		t.Fatalf("response status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Join(calls, ",") != "approve,plan" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestControlAPIRejectsPartialGoalPlanConfiguration(t *testing.T) {
	_, err := New(Config{
		Store: eventing.NewMemoryStore(),
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: &recordingAuthorizer{}, GoalPlan: GoalPlanServices{Negotiator: &recordingGoalNegotiator{}},
	})
	if err == nil {
		t.Fatal("expected partial goal plan configuration to fail")
	}
}

func newGoalPlanTestHandler(t *testing.T, negotiator GoalNegotiationService, planner GoalPlanningService) (*Handler, *eventing.MemoryStore, *recordingAuthorizer) {
	t.Helper()
	store := eventing.NewMemoryStore()
	authorizer := &recordingAuthorizer{}
	handler, err := New(Config{
		Store: store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: authorizer, Artifacts: &testArtifactCatalog{}, Knowledge: &testKnowledgeReader{},
		GoalPlan: GoalPlanServices{Negotiator: negotiator, Planner: planner},
		Clock:    func() time.Time { return controlAPITestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, authorizer
}

func requireGoalPlanUUIDv7(t *testing.T, value string) {
	t.Helper()
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.Version() != uuid.Version(7) {
		t.Fatalf("record id %q is not UUIDv7", value)
	}
}

var _ GoalNegotiationService = (*recordingGoalNegotiator)(nil)
var _ GoalPlanningService = (*recordingGoalPlanner)(nil)
