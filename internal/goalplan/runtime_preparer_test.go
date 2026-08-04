package goalplan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/prompts"
)

const runtimePreparerPolicy = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAuthoritativeRuntimePreparerBuildsInitialGoalInvocation(t *testing.T) {
	now := time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC)
	project := state.Project{
		TenantID: "tenant_1", ID: "project_1", Version: 3, State: contracts.ProjectGoalNegotiating,
		PromptBundleVersion: prompts.BaselineVersion, DataClassification: "INTERNAL",
	}
	message := runtimePreparerArtifact(t, now, ArtifactUserMessage, "message_1", 1, []byte("Build an auditable service"), "")
	issuer := &runtimePreparerIssuer{now: now, project: project}
	preparer := newRuntimePreparer(t, now, project, state.ModuleTask{}, issuer, message)
	request := AgentInvocation{
		InvocationID: "run_goal_1", TenantID: project.TenantID, ProjectID: project.ID,
		Role: agentruntime.RoleGoalProposer, Stage: "GOAL_DRAFT", Inputs: []ArtifactPointer{artifactPointer(message)},
	}

	prepared, err := preparer.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Declaration.AgentInstanceID != "project_1:GOAL_PROPOSER" || prepared.Lease.AgentInstanceID != prepared.Declaration.AgentInstanceID || prepared.Intent != aop.IntentProposeGoal {
		t.Fatalf("prepared identity = %#v", prepared)
	}
	if prepared.Declaration.Envelope.GoalSpec != nil || prepared.Declaration.Envelope.Scope != aop.ScopeProject || prepared.Declaration.Envelope.ExpectedAggregateVersion != project.Version {
		t.Fatalf("goal envelope = %#v", prepared.Declaration.Envelope)
	}
	items := prepared.Declaration.ContextManifest.Items
	if len(items) != 1 || items[0].Kind != agentruntime.ContextUserInput || items[0].Trust != agentruntime.TrustExternalUntrusted || items[0].Content != string(message.Content) {
		t.Fatalf("goal context = %#v", items)
	}
	if issuer.request.Action != authz.ActionModelGenerate || issuer.request.TaskID != "" || issuer.request.BudgetAccountID != project.ID || issuer.request.ParameterDigest == "" {
		t.Fatalf("lease request = %#v", issuer.request)
	}
	if prepared.ModelCall.Provider != "openai-primary" || prepared.ModelCall.Model != "model-test" || prepared.ModelCall.ReservationID == "" {
		t.Fatalf("model call = %#v", prepared.ModelCall)
	}
	runtime := newGoalPlanRuntime(t, now, &runtimeInvokerGateway{}, &runtimeInvokerAuthority{})
	if err := runtime.Declare(prepared.Declaration); err != nil {
		t.Fatalf("declare prepared goal invocation: %v", err)
	}

	forged := request
	forged.Inputs = append([]ArtifactPointer(nil), request.Inputs...)
	forged.Inputs[0].URI = "artifact://sha256/forged"
	if _, err := preparer.Prepare(context.Background(), forged); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("forged pointer error = %v", err)
	}
}

func TestAuthoritativeRuntimePreparerBindsModuleToDurablePlanningTask(t *testing.T) {
	now := time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC)
	goalContent := validGoalContent("approved goal")
	goalContent.ProjectID = "project_1"
	goalContent.Version = 1
	goalContent.CreatedAt = now.Format(time.RFC3339Nano)
	goalContent.CreatedBy = contracts.AgentIdentity{AgentInstanceID: "project_1:GOAL_PROPOSER", Role: string(agentruntime.RoleGoalProposer)}
	goal, goalJSON, err := encodeGoal(goalContent, contracts.GoalApproved, &contracts.ApprovalActor{ActorID: "user_1", ApprovedAt: now.Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	goalArtifact := runtimePreparerArtifact(t, now, ArtifactGoalApproved, "goal_1", 1, goalJSON, goal.ContentSHA256)
	goalRef := runtimeArtifactRef(goalArtifact)
	planDraft, err := json.Marshal(validPlanDraft())
	if err != nil {
		t.Fatal(err)
	}
	plan, planJSON, err := normalizePlanRecord(AgentRecord{
		RunID: "run_plan", AgentInstanceID: "project_1:PLAN_SUPERVISOR",
		Role: agentruntime.RolePlanSupervisor, Payload: planDraft,
	}, "project_1", goalRef, 1)
	if err != nil {
		t.Fatal(err)
	}
	planArtifact := runtimePreparerArtifact(t, now, ArtifactPlanSpec, "plan_1", 1, planJSON, plan.SHA256)
	planRef := runtimeArtifactRef(planArtifact)
	project := state.Project{
		TenantID: "tenant_1", ID: "project_1", Version: 5, State: contracts.ProjectPlanning,
		PromptBundleVersion: prompts.BaselineVersion, DataClassification: "CONFIDENTIAL",
		Goal: &state.GoalRecord{
			ID: "goal_1", Version: goalRef.Version, SHA256: goalRef.SHA256,
			Status: contracts.GoalApproved, ApprovedBy: "user_1",
		},
	}
	module := plan.Modules[0]
	payload, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	task := state.ModuleTask{
		TenantID: project.TenantID, ProjectID: project.ID, ID: "task_1", ModuleID: module.ModuleID,
		State: contracts.TaskPlanning, Version: 2, PlanningSpecRef: planRef,
	}
	issuer := &runtimePreparerIssuer{now: now, project: project, task: task}
	preparer := newRuntimePreparer(t, now, project, task, issuer, goalArtifact, planArtifact)
	request := AgentInvocation{
		InvocationID: "run_module_1", TenantID: project.TenantID, ProjectID: project.ID, TaskID: task.ID,
		Role: agentruntime.RoleModulePlanner, Stage: "MODULE_SPEC",
		Inputs: []ArtifactPointer{artifactPointer(goalArtifact), artifactPointer(planArtifact)}, Payload: payload,
	}

	prepared, err := preparer.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Declaration.AgentInstanceID != "project_1:MODULE_PLANNER:task_1" || prepared.Declaration.Envelope.Scope != aop.ScopeTask || prepared.Declaration.Envelope.ExpectedAggregateVersion != task.Version {
		t.Fatalf("module declaration = %#v", prepared.Declaration)
	}
	if prepared.Declaration.Envelope.GoalSpec == nil || *prepared.Declaration.Envelope.GoalSpec != goalRef || prepared.Declaration.Envelope.PlanSpec == nil || *prepared.Declaration.Envelope.PlanSpec != planRef {
		t.Fatalf("module references = %#v", prepared.Declaration.Envelope)
	}
	if issuer.lease.TaskVersion != task.Version || issuer.lease.SpecDigest != task.PlanningSpecRef.SHA256 || issuer.request.TaskID != task.ID {
		t.Fatalf("module lease = %#v request=%#v", issuer.lease, issuer.request)
	}
	foundTaskContext := false
	for _, item := range prepared.Declaration.ContextManifest.Items {
		if item.Kind == agentruntime.ContextTaskState && item.Content == string(payload) {
			foundTaskContext = true
		}
	}
	if !foundTaskContext {
		t.Fatalf("task context missing: %#v", prepared.Declaration.ContextManifest.Items)
	}
	runtime := newGoalPlanRuntime(t, now, &runtimeInvokerGateway{}, &runtimeInvokerAuthority{})
	if err := runtime.Declare(prepared.Declaration); err != nil {
		t.Fatalf("declare prepared module invocation: %v", err)
	}

	mismatched := request
	changed := module
	changed.Name = "other module"
	mismatched.Payload, _ = json.Marshal(changed)
	if _, err := preparer.Prepare(context.Background(), mismatched); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatched assignment error = %v", err)
	}
}

type runtimePreparerArtifacts struct {
	values []SpecArtifact
}

func (store runtimePreparerArtifacts) Put(context.Context, SpecArtifact) (SpecArtifact, error) {
	return SpecArtifact{}, ErrInvalidRequest
}

func (store runtimePreparerArtifacts) Get(_ context.Context, tenantID, projectID string, kind ArtifactKind, specID string, version int) (SpecArtifact, bool, error) {
	for _, artifact := range store.values {
		if artifact.TenantID == tenantID && artifact.ProjectID == projectID && artifact.Kind == kind && artifact.SpecID == specID && artifact.Version == version {
			return cloneArtifact(artifact), true, nil
		}
	}
	return SpecArtifact{}, false, nil
}

type runtimePreparerReader struct {
	project state.Project
	task    state.ModuleTask
}

func (reader runtimePreparerReader) Project(_ context.Context, tenantID, projectID string) (state.Project, bool, error) {
	return reader.project, reader.project.TenantID == tenantID && reader.project.ID == projectID, nil
}

func (reader runtimePreparerReader) Task(_ context.Context, tenantID, projectID, taskID string) (state.ModuleTask, bool, error) {
	return reader.task, reader.task.TenantID == tenantID && reader.task.ProjectID == projectID && reader.task.ID == taskID, nil
}

type runtimePreparerIssuer struct {
	now       time.Time
	project   state.Project
	task      state.ModuleTask
	principal authn.Principal
	request   leaseauthority.GrantRequest
	lease     authz.CapabilityLease
}

func (issuer *runtimePreparerIssuer) Issue(_ context.Context, principal authn.Principal, request leaseauthority.GrantRequest) (authz.CapabilityLease, error) {
	issuer.principal, issuer.request = principal, request
	lease := authz.CapabilityLease{
		ID: stableRuntimeID("lease_", principal.ID, request.IdempotencyKey), AgentInstanceID: principal.ID,
		PrincipalID: principal.ID, PrincipalType: principal.Type, TenantID: request.TenantID, ProjectID: request.ProjectID,
		ProjectVersion: issuer.project.Version, TaskID: request.TaskID, Role: principal.Role,
		Action: request.Action, Resource: request.Resource, ParameterDigest: request.ParameterDigest,
		Capabilities: []string{request.Action}, IssuedAt: issuer.now, ExpiresAt: issuer.now.Add(5 * time.Minute),
		LastHeartbeatAt: issuer.now, HeartbeatIntervalSeconds: agentruntime.DefaultHeartbeatSeconds,
		PolicyVersion: runtimePreparerPolicy, BudgetAccountID: request.BudgetAccountID,
		Nonce:        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		FencingToken: 1, State: authz.LeaseActive, Signature: "hmac-sha256:test",
	}
	if request.TaskID != "" {
		lease.TaskVersion = issuer.task.Version
		lease.SpecDigest = issuer.task.PlanningSpecRef.SHA256
	}
	issuer.lease = lease
	return lease, nil
}

func newRuntimePreparer(t *testing.T, now time.Time, project state.Project, task state.ModuleTask, issuer *runtimePreparerIssuer, artifacts ...SpecArtifact) *AuthoritativeRuntimePreparer {
	t.Helper()
	reader := runtimePreparerReader{project: project, task: task}
	route := ModelRoute{
		Provider: "openai-primary", Model: "model-test", MaxOutputTokens: 1024,
		Temperature: 0, ProviderPolicy: "default", CachePolicy: "NO_STORE",
		WorstCaseCostMicros: 1000, MaxAttempts: 1,
	}
	routes := map[agentruntime.Role]ModelRoute{
		agentruntime.RoleGoalProposer: route, agentruntime.RoleGoalChallenger: route,
		agentruntime.RolePlanSupervisor: route, agentruntime.RoleModulePlanner: route,
	}
	preparer, err := NewAuthoritativeRuntimePreparer(RuntimePreparerConfig{
		Artifacts: runtimePreparerArtifacts{values: artifacts}, Projects: reader, Tasks: reader,
		Leases: issuer, Routes: routes, LeaseTTL: 5 * time.Minute, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return preparer
}

func runtimePreparerArtifact(t *testing.T, now time.Time, kind ArtifactKind, specID string, version int, content []byte, contentSHA string) SpecArtifact {
	t.Helper()
	artifact := SpecArtifact{
		TenantID: "tenant_1", ProjectID: "project_1", Kind: kind, SpecID: specID, Version: version,
		ContentSHA256: contentSHA, Content: append([]byte(nil), content...), CreatedAt: now,
		CreatedBy: "project_1:GOAL_PROPOSER",
	}
	if err := prepareArtifact(&artifact); err != nil {
		t.Fatal(err)
	}
	return artifact
}
