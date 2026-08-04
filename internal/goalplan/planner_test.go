package goalplan

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/pkg/contracts"
)

type scriptedPlanningInvoker struct {
	plan        contracts.PlanSpec
	invocations []AgentInvocation
}

func (i *scriptedPlanningInvoker) Invoke(_ context.Context, invocation AgentInvocation) (AgentRecord, error) {
	i.invocations = append(i.invocations, invocation)
	switch invocation.Role {
	case agentruntime.RolePlanSupervisor:
		payload, _ := json.Marshal(i.plan)
		return AgentRecord{RunID: invocation.InvocationID, AgentInstanceID: "agt_plan", Role: invocation.Role, Payload: payload}, nil
	case agentruntime.RoleModulePlanner:
		var planned contracts.PlanModule
		if err := json.Unmarshal(invocation.Payload, &planned); err != nil {
			return AgentRecord{}, err
		}
		payload, _ := json.Marshal(validModuleDraft(planned))
		return AgentRecord{RunID: invocation.InvocationID, AgentInstanceID: "agt_module_" + planned.ModuleID, Role: invocation.Role, Payload: payload}, nil
	default:
		return AgentRecord{}, ErrAgentOutput
	}
}

func TestPlannerPublishesValidatedPlanAndAllTasksAtomically(t *testing.T) {
	planner, invoker, request := approvedPlanningHarness(t)
	result, err := planner.BuildAndPublish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Publication.Project.State != contracts.ProjectExecuting || len(result.Publication.Tasks) != 2 || len(result.ModuleSpecs) != 2 {
		t.Fatalf("planning result = %#v", result)
	}
	if !slices.Equal(result.Analysis.TopologicalOrder, []string{"mod_api", "mod_worker"}) || !slices.Equal(result.Analysis.CriticalPath, []string{"mod_api", "mod_worker"}) {
		t.Fatalf("analysis = %#v", result.Analysis)
	}
	if result.ModuleSpecs["mod_api"].AllowedPaths[0] != "internal/api" || result.ModuleSpecs["mod_worker"].Dependencies[0] != "mod_api" {
		t.Fatalf("module specs = %#v", result.ModuleSpecs)
	}
	if len(invoker.invocations) != 3 {
		t.Fatalf("agent invocations = %d", len(invoker.invocations))
	}
	replayed, err := planner.BuildAndPublish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Publication.Duplicate || len(invoker.invocations) != 3 {
		t.Fatalf("replay = %#v invocations=%d", replayed.Publication, len(invoker.invocations))
	}
}

func TestPlannerPublishesAgentPlanAsAuthenticatedUser(t *testing.T) {
	planner, _, request := approvedPlanningHarness(t)
	commander := &principalRecordingCommander{delegate: planner.projects}
	planner.projects = commander
	if _, err := planner.BuildAndPublish(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(commander.published) != 1 || commander.published[0] != "usr_1" {
		t.Fatalf("plan commit principals = %#v", commander.published)
	}
}

func TestPlannerAutomaticallyAllocatesStableProductionTaskIdentities(t *testing.T) {
	planner, invoker, request := approvedPlanningHarness(t)
	request.ModuleTaskIDs = nil
	request.AttemptSeriesIDs = nil
	request.ModuleSpecVersions = nil
	result, err := planner.BuildAndPublishAutomatic(context.Background(), request)
	if err != nil {
		project, _, _ := planner.projects.Project(context.Background(), request.TenantID, request.ProjectID)
		t.Fatalf("automatic planning: %v project=%#v request=%#v", err, project, request)
	}
	if len(result.Publication.Tasks) != 2 || len(invoker.invocations) != 3 {
		t.Fatalf("automatic planning result = %#v invocations=%d", result.Publication, len(invoker.invocations))
	}
	invocationTasks := make(map[string]bool, 2)
	for _, invocation := range invoker.invocations {
		if invocation.Role == agentruntime.RoleModulePlanner {
			invocationTasks[invocation.TaskID] = true
		}
	}
	firstIDs := make(map[string]string, len(result.Publication.Tasks))
	for _, task := range result.Publication.Tasks {
		if _, err := uuid.Parse(task.ID); err != nil {
			t.Fatalf("task ID %q is not a UUID: %v", task.ID, err)
		}
		if _, err := uuid.Parse(task.AttemptSeriesID); err != nil {
			t.Fatalf("attempt series ID %q is not a UUID: %v", task.AttemptSeriesID, err)
		}
		if !invocationTasks[task.ID] {
			t.Fatalf("module planner was not bound to task %q", task.ID)
		}
		firstIDs[task.ModuleSpecRef.SHA256] = task.ID + "/" + task.AttemptSeriesID
	}
	replayed, err := planner.BuildAndPublishAutomatic(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Publication.Duplicate || len(invoker.invocations) != 3 {
		t.Fatalf("automatic replay = %#v invocations=%d", replayed.Publication, len(invoker.invocations))
	}
	for _, task := range replayed.Publication.Tasks {
		if firstIDs[task.ModuleSpecRef.SHA256] != task.ID+"/"+task.AttemptSeriesID {
			t.Fatalf("automatic identity changed on replay: %#v", task)
		}
	}
}

func TestPlannerRejectsOverlappingModuleOwnershipBeforePublication(t *testing.T) {
	planner, invoker, request := approvedPlanningHarness(t)
	invoker.plan.Modules[1].OwnedPaths = []string{"internal/api/private"}
	_, err := planner.BuildAndPublish(context.Background(), request)
	if !errors.Is(err, ErrAgentOutput) {
		t.Fatalf("overlap = %v", err)
	}
	project, found, queryErr := planner.projects.Project(context.Background(), request.TenantID, request.ProjectID)
	if queryErr != nil || !found || project.State != contracts.ProjectPlanning || project.Plan != nil {
		t.Fatalf("project = %#v found %v err %v", project, found, queryErr)
	}
}

func TestPlannerRequiresApprovedGoalArtifact(t *testing.T) {
	negotiator, _, service := negotiationHarness(t, 1)
	draft, err := negotiator.Negotiate(context.Background(), NegotiationRequest{TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: "msg_1", UserPrincipalID: "usr_1", UserInput: []byte("build"), GoalAgentCount: 1, ExpectedProjectVersion: 2, IdempotencyKey: "draft"})
	if err != nil {
		t.Fatal(err)
	}
	invoker := &scriptedPlanningInvoker{plan: validPlanDraft()}
	planner, _ := NewPlanner(negotiator.artifacts, invoker, service, goalPlanClock)
	_, err = planner.BuildAndPublish(context.Background(), PlanningRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", GoalSpecID: "goal_1", GoalRef: contracts.SpecRef{Version: draft.Goal.Content.Version, SHA256: draft.Goal.ContentSHA256}, PlanSpecID: "plan_1", PlanVersion: 1, ModuleTaskIDs: map[string]string{"mod_api": "task_api", "mod_worker": "task_worker"}, AttemptSeriesIDs: map[string]string{"mod_api": "series_api", "mod_worker": "series_worker"}, ModuleSpecVersions: map[string]int{"mod_api": 1, "mod_worker": 1}, ExpectedProjectVersion: 3, IdempotencyKey: "plan"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unapproved planning = %v", err)
	}
}

func TestApprovedGoalChangeSupersedesOnlyImpactedTasks(t *testing.T) {
	planner, _, planRequest := approvedPlanningHarness(t)
	if _, err := planner.BuildAndPublish(context.Background(), planRequest); err != nil {
		t.Fatal(err)
	}
	service := planner.projects.(*orchestrator.Service)
	invoker := &scriptedGoalInvoker{}
	negotiator, err := NewNegotiator(planner.artifacts, invoker, service, goalPlanClock)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := negotiator.Negotiate(context.Background(), NegotiationRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: "msg_change", UserPrincipalID: "usr_1",
		UserInput: []byte("change only the API"), GoalAgentCount: 1, PreviousRef: &planRequest.GoalRef, SupersedeApprovedGoal: true,
		ImpactedTaskIDs: []string{"task_api"}, ExpectedProjectVersion: 5, IdempotencyKey: "change_goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Project.Project.State != contracts.ProjectGoalNegotiating || changed.Project.Project.Plan != nil || changed.Goal.Content.Version != 2 {
		t.Fatalf("changed project = %#v", changed)
	}
	apiTask, found, err := service.Task(context.Background(), "tenant_1", "prj_1", "task_api")
	if err != nil || !found || apiTask.State != contracts.TaskSuperseded {
		t.Fatalf("API task = %#v found=%v err=%v", apiTask, found, err)
	}
	workerTask, found, err := service.Task(context.Background(), "tenant_1", "prj_1", "task_worker")
	if err != nil || !found || workerTask.State != contracts.TaskDefined {
		t.Fatalf("worker task = %#v found=%v err=%v", workerTask, found, err)
	}
	changedRef := contracts.SpecRef{Version: changed.Goal.Content.Version, SHA256: changed.Goal.ContentSHA256}
	if _, err := negotiator.Approve(context.Background(), ApprovalRequest{TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", GoalRef: changedRef, UserPrincipalID: "usr_1", ExpectedProjectVersion: 6, IdempotencyKey: "approve_changed", Approval: ApprovalBinding{RecordID: "approval_changed", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: "goal_1", SubjectVersion: changedRef.Version, SubjectSHA256: changedRef.SHA256, PrincipalID: "usr_1", Reason: "approve change", IssuedAt: goalPlanClock(), Signature: "signed"}}); err != nil {
		t.Fatal(err)
	}
	replanInvoker := &scriptedPlanningInvoker{plan: validPlanDraft()}
	replanner, err := NewPlanner(planner.artifacts, replanInvoker, service, goalPlanClock)
	if err != nil {
		t.Fatal(err)
	}
	replanned, err := replanner.BuildAndPublish(context.Background(), PlanningRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", GoalSpecID: "goal_1", GoalRef: changedRef, PlanSpecID: "plan_2", PlanVersion: 2,
		ModuleTaskIDs: map[string]string{"mod_api": "task_api_v2", "mod_worker": "task_worker"}, AttemptSeriesIDs: map[string]string{"mod_api": "series_api_v2", "mod_worker": "series_worker"},
		ModuleSpecVersions: map[string]int{"mod_api": 2, "mod_worker": 1}, RetainedModules: map[string]bool{"mod_worker": true},
		ExpectedProjectVersion: 7, IdempotencyKey: "publish_plan_v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if replanned.Publication.Project.State != contracts.ProjectExecuting || len(replanInvoker.invocations) != 2 || replanned.ModuleSpecs["mod_worker"].ModuleSpecVersion != 1 || replanned.ModuleSpecs["mod_api"].ModuleSpecVersion != 2 {
		t.Fatalf("replanned = %#v calls=%d", replanned, len(replanInvoker.invocations))
	}
	retainedWorker, _, _ := service.Task(context.Background(), "tenant_1", "prj_1", "task_worker")
	newAPI, found, err := service.Task(context.Background(), "tenant_1", "prj_1", "task_api_v2")
	if err != nil || !found || retainedWorker.Version != workerTask.Version || newAPI.State != contracts.TaskDefined || !slices.Equal(newAPI.DependentTaskIDs, []string{"task_worker"}) {
		t.Fatalf("retained=%#v new=%#v found=%v err=%v", retainedWorker, newAPI, found, err)
	}
}

func approvedPlanningHarness(t *testing.T) (*Planner, *scriptedPlanningInvoker, PlanningRequest) {
	t.Helper()
	negotiator, _, service := negotiationHarness(t, 1)
	draft, err := negotiator.Negotiate(context.Background(), NegotiationRequest{TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", MessageID: "msg_1", UserPrincipalID: "usr_1", UserInput: []byte("build"), GoalAgentCount: 1, ExpectedProjectVersion: 2, IdempotencyKey: "draft"})
	if err != nil {
		t.Fatal(err)
	}
	ref := contracts.SpecRef{Version: draft.Goal.Content.Version, SHA256: draft.Goal.ContentSHA256}
	if _, err := negotiator.Approve(context.Background(), ApprovalRequest{TenantID: "tenant_1", ProjectID: "prj_1", GoalSpecID: "goal_1", GoalRef: ref, UserPrincipalID: "usr_1", ExpectedProjectVersion: 3, IdempotencyKey: "approve", Approval: validGoalApproval(ref)}); err != nil {
		t.Fatal(err)
	}
	invoker := &scriptedPlanningInvoker{plan: validPlanDraft()}
	planner, err := NewPlanner(negotiator.artifacts, invoker, service, goalPlanClock)
	if err != nil {
		t.Fatal(err)
	}
	request := PlanningRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", GoalSpecID: "goal_1", GoalRef: ref, PlanSpecID: "plan_1", PlanVersion: 1,
		ModuleTaskIDs:          map[string]string{"mod_api": "task_api", "mod_worker": "task_worker"},
		AttemptSeriesIDs:       map[string]string{"mod_api": "series_api", "mod_worker": "series_worker"},
		ModuleSpecVersions:     map[string]int{"mod_api": 1, "mod_worker": 1},
		ExpectedProjectVersion: 4, IdempotencyKey: "publish_plan",
	}
	return planner, invoker, request
}

func validPlanDraft() contracts.PlanSpec {
	return contracts.PlanSpec{
		Architecture:      contracts.Architecture{Style: "modular", Components: []string{"api", "worker"}, DataFlows: []string{"api to worker"}, TrustBoundaries: []string{"http"}, DeploymentUnits: []string{"service"}},
		QualityAttributes: []string{"secure"},
		Modules: []contracts.PlanModule{
			{ModuleID: "mod_api", Name: "API", Responsibility: "own the HTTP boundary", ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer, OwnedPaths: []string{"internal/api"}, ForbiddenPaths: []string{".git", "policies"}, PublicInterfaces: []string{"HTTP v1"}, Dependencies: []string{}, AcceptanceCriteria: []string{"API contract passes"}, Risk: "HIGH"},
			{ModuleID: "mod_worker", Name: "Worker", Responsibility: "own background processing", ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer, OwnedPaths: []string{"internal/worker"}, ForbiddenPaths: []string{".git", "policies"}, PublicInterfaces: []string{}, Dependencies: []string{"mod_api"}, AcceptanceCriteria: []string{"worker tests pass"}, Risk: "MEDIUM"},
		},
		IntegrationPlan: []string{"merge in topological order"}, ReleasePlan: []string{"signed release"}, TestStrategy: []string{"unit and integration"}, RollbackStrategy: []string{"restore previous release"}, OpenDecisions: []string{},
	}
}

func validModuleDraft(planned contracts.PlanModule) contracts.ModuleSpec {
	return contracts.ModuleSpec{
		Name: planned.Name, Purpose: planned.Responsibility, Responsibilities: []string{"implementation details"}, NonResponsibilities: []string{},
		Inputs: []string{}, Outputs: []string{}, Interfaces: []string{}, DataOwnership: []string{}, Dependencies: []string{}, AllowedPaths: []string{"/malicious/agent/path"}, ForbiddenPaths: []string{},
		NetworkPolicy: contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll, Destinations: []string{}}, WorkloadProfile: contracts.WorkloadProfile{Trust: contracts.WorkloadUntrusted},
		ToolCapabilities: []string{"repo.read", "repo.write"}, KnowledgeRefs: []string{}, AcceptanceCriteria: []string{"agent claim"}, TestRequirements: []string{"go test"},
		ObservabilityRequirements: []string{"trace"}, SecurityRequirements: []string{"least privilege"}, Budget: contracts.Budget{MaxInputTokens: 1000, MaxOutputTokens: 1000, MaxCost: "1.00", Currency: "USD"},
	}
}

var _ ProjectCommander = (*orchestrator.Service)(nil)
