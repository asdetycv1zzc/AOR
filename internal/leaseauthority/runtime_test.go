package leaseauthority

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestRuntimeAuthorityValidatesHeartbeatsAndRenewsSignedLease(t *testing.T) {
	now := time.Date(2035, 3, 4, 5, 6, 7, 0, time.UTC)
	signer, err := authz.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: authz.NewMemoryLeaseStore(), Signer: signer, Clock: func() time.Time { return now },
		DefaultTTL: 5 * time.Minute, MaxTTL: 15 * time.Minute, HeartbeatInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{
		ID: "agent_goal", Type: authn.PrincipalAgentInstance, Role: authn.RoleGoalProposer,
		TenantID: "tenant_1", ProjectID: "project_1",
	}
	scopes := &fixedScopeResolver{scope: Scope{
		Project: authz.ProjectScope{
			TenantID: principal.TenantID, ID: principal.ProjectID, State: "GOAL_NEGOTIATING",
			StateVersion: 4, Classification: "INTERNAL",
		},
		Budget: authz.BudgetScope{AccountID: "project_1", Available: true},
	}}
	service, err := New(Config{Manager: manager, Policy: &bindingGrantEvaluator{}, Scopes: scopes, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	principalCtx, err := authn.ContextWithPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(principalCtx, principal, GrantRequest{
		TenantID: principal.TenantID, ProjectID: principal.ProjectID,
		Action: authz.ActionModelGenerate, Resource: authz.Resource{Type: "model", ID: "provider/model"},
		ParameterDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		BudgetAccountID: "project_1", IdempotencyKey: "runtime-lease-1", TTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewRuntimeAuthority(service, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, dynamic := authority.(agentruntime.OperationLeaseAuthority); dynamic {
		t.Fatal("base runtime authority unexpectedly derives operation leases")
	}
	lease := toRuntimeLease(issued)
	if err := authority.Validate(context.Background(), lease, agentruntime.LeaseOperationModel); err != nil {
		t.Fatalf("validate model lease: %v", err)
	}
	if err := authority.Validate(context.Background(), lease, agentruntime.LeaseOperationTool); !errors.Is(err, agentruntime.ErrLeaseInvalid) {
		t.Fatalf("model lease used for tool error = %v", err)
	}
	tampered := lease
	tampered.ProjectID = "project_other"
	if err := authority.Validate(context.Background(), tampered, agentruntime.LeaseOperationModel); !errors.Is(err, agentruntime.ErrLeaseInvalid) {
		t.Fatalf("tampered lease error = %v", err)
	}

	now = now.Add(10 * time.Second)
	heartbeat, err := authority.Heartbeat(context.Background(), lease)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !heartbeat.LastHeartbeatAt.Equal(now) || heartbeat.FencingToken != lease.FencingToken || heartbeat.Nonce != lease.Nonce || heartbeat.Signature == lease.Signature {
		t.Fatalf("heartbeat lease = %#v", heartbeat)
	}

	now = now.Add(10 * time.Second)
	renewed, err := authority.Renew(context.Background(), heartbeat)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.FencingToken != heartbeat.FencingToken+1 || renewed.Nonce == heartbeat.Nonce || !renewed.ExpiresAt.After(heartbeat.ExpiresAt) {
		t.Fatalf("renewed lease = %#v", renewed)
	}
	if err := authority.Validate(context.Background(), renewed, agentruntime.LeaseOperationRenew); err != nil {
		t.Fatalf("validate renewed lease: %v", err)
	}

	now = now.Add(91 * time.Second)
	if err := authority.Validate(context.Background(), renewed, agentruntime.LeaseOperationModel); !errors.Is(err, agentruntime.ErrLeaseExpired) {
		t.Fatalf("expired lease error = %v", err)
	}
}

func TestRuntimeOperationAuthorityIssuesExactModelAndToolSubleases(t *testing.T) {
	service, _, _, principal := testService(t)
	ctx := principalContext(t, principal)
	call := agentruntime.ModelCall{
		RequestID: "model-request-1", Provider: "provider", Model: "model",
		ReservationID: "reservation-1", MaxOutputTokens: 100, ProviderPolicy: "default",
		CachePolicy: "disabled", MaxAttempts: 1,
	}
	_, modelDigest, err := agentruntime.ModelOperationBinding(call)
	if err != nil {
		t.Fatal(err)
	}
	base, err := service.IssueExecution(ctx, principal, GrantRequest{
		TenantID: principal.TenantID, ProjectID: principal.ProjectID, TaskID: "task_1",
		Action: authz.ActionModelGenerate, Resource: authz.Resource{Type: "model", ID: "provider/model"},
		ParameterDigest: modelDigest, BudgetAccountID: "budget_1", IdempotencyKey: "execution-model-lease", TTL: 2 * time.Minute,
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDescriptorToolResolver([]toolbroker.ToolDescriptor{runtimeToolDescriptor()})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewRuntimeOperationAuthority(service, 5*time.Minute, resolver)
	if err != nil {
		t.Fatal(err)
	}
	executionLease := toRuntimeLease(base)
	modelLease, err := authority.AcquireOperationLease(ctx, executionLease, agentruntime.OperationLeaseRequest{
		Operation: agentruntime.LeaseOperationModel, RequestID: call.RequestID,
		Provider: call.Provider, Model: call.Model, ModelCall: call,
	})
	if err != nil || modelLease.LeaseID != executionLease.LeaseID || authority.Validate(ctx, modelLease, agentruntime.LeaseOperationModel) != nil {
		t.Fatalf("model lease=%#v err=%v", modelLease, err)
	}
	parameters := json.RawMessage(`{"attempt":1}`)
	toolLease, err := authority.AcquireOperationLease(ctx, executionLease, agentruntime.OperationLeaseRequest{
		Operation: agentruntime.LeaseOperationTool, RequestID: "tool-request-1",
		ToolID: "repository.file.read", ToolVersion: "1.0.0", Parameters: parameters,
	})
	if err != nil {
		t.Fatal(err)
	}
	if toolLease.LeaseID == executionLease.LeaseID || toolLease.FencingToken != 7 || !toolLease.ExpiresAt.Equal(executionLease.ExpiresAt) || authority.Validate(ctx, toolLease, agentruntime.LeaseOperationTool) != nil {
		t.Fatalf("tool lease = %#v", toolLease)
	}
	replayed, err := authority.AcquireOperationLease(ctx, executionLease, agentruntime.OperationLeaseRequest{
		Operation: agentruntime.LeaseOperationTool, RequestID: "tool-request-1",
		ToolID: "repository.file.read", ToolVersion: "1.0.0", Parameters: parameters,
	})
	if err != nil || replayed.LeaseID != toolLease.LeaseID || replayed.Signature != toolLease.Signature {
		t.Fatalf("replayed tool lease = %#v err=%v", replayed, err)
	}
	stored, found, err := service.manager.GetForTenant(ctx, principal.TenantID, toolLease.LeaseID)
	if err != nil || !found {
		t.Fatalf("stored tool lease found=%t err=%v", found, err)
	}
	digest, err := toolbroker.AuthorizationParameterDigest(parameters)
	if err != nil || stored.Action != authz.ActionToolInvoke || stored.ParameterDigest != digest || stored.Resource.Path != executionLease.LeaseID {
		t.Fatalf("stored tool lease = %#v digestErr=%v", stored, err)
	}
}

func TestRuntimeOperationAuthorityRunsModelToolLoop(t *testing.T) {
	service, _, _, principal := testService(t)
	ctx := principalContext(t, principal)
	descriptor := runtimeToolDescriptor()
	manager, ok := service.manager.(toolbroker.AuthzLeaseValidator)
	if !ok {
		t.Fatal("lease manager does not expose authoritative validation")
	}
	executor := &runtimeToolExecutor{}
	broker := toolbroker.New(
		toolbroker.AuthzLeaseChecker{Manager: manager, Scopes: runtimeToolScopes{}},
		runtimeToolPolicy{}, executor, nil, runtimeToolRecorder{}, nil,
		func() time.Time { return leaseTestNow },
	)
	if err := broker.Register(descriptor); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDescriptorToolResolver(broker.List())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewRuntimeOperationAuthority(service, 5*time.Minute, resolver)
	if err != nil {
		t.Fatal(err)
	}
	call := agentruntime.ModelCall{
		RequestID: "model-request-loop", Provider: "provider", Model: "model",
		ReservationID: "reservation-loop", MaxOutputTokens: 128, ProviderPolicy: "default",
		CachePolicy: "disabled", MaxAttempts: 1,
	}
	_, modelDigest, err := agentruntime.ModelOperationBinding(call)
	if err != nil {
		t.Fatal(err)
	}
	base, err := service.IssueExecution(ctx, principal, GrantRequest{
		TenantID: principal.TenantID, ProjectID: principal.ProjectID, TaskID: "task_1",
		Action: authz.ActionModelGenerate, Resource: authz.Resource{Type: "model", ID: "provider/model"},
		ParameterDigest: modelDigest, BudgetAccountID: "budget_1", IdempotencyKey: "execution-loop-lease", TTL: 5 * time.Minute,
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &runtimeLoopGateway{responses: []modelgateway.NormalizedResponse{
		{ToolCalls: []modelgateway.ToolCall{{ID: "tool-request-loop", Name: descriptor.ToolID, Arguments: json.RawMessage(`{"path":"README.md"}`)}}},
		{Content: json.RawMessage(`{"intent":"SUBMIT_IMPLEMENTATION"}`)},
	}}
	slots, err := agentruntime.NewSlotPool(1, func() time.Time { return leaseTestNow })
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := agentruntime.New(authority, gateway, broker, slots, func() time.Time { return leaseTestNow })
	if err != nil {
		t.Fatal(err)
	}
	declaration := runtimeExecutionDeclaration(base, descriptor)
	if err := runtime.Declare(declaration); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Queue(declaration.RunID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AssignLease(ctx, declaration.RunID, toRuntimeLease(base)); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(ctx, declaration.RunID); err != nil {
		t.Fatal(err)
	}
	response, err := runtime.RunToolLoop(ctx, declaration.RunID, call, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Content) != `{"intent":"SUBMIT_IMPLEMENTATION"}` || len(gateway.requests) != 2 {
		t.Fatalf("response=%#v modelCalls=%d", response, len(gateway.requests))
	}
	if !executor.found || executor.authorization.ExecutionLeaseID != base.ID || executor.authorization.Lease.ID == base.ID || executor.authorization.Lease.FencingToken != 7 {
		t.Fatalf("tool authorization = %#v found=%t", executor.authorization, executor.found)
	}
	stored, found, err := service.manager.GetForTenant(ctx, principal.TenantID, executor.authorization.Lease.ID)
	if err != nil || !found || stored.Action != authz.ActionToolInvoke || stored.Resource.Path != base.ID {
		t.Fatalf("stored operation lease=%#v found=%t err=%v", stored, found, err)
	}
}

type runtimeLoopGateway struct {
	responses []modelgateway.NormalizedResponse
	requests  []modelgateway.NormalizedRequest
}

func (gateway *runtimeLoopGateway) Generate(_ context.Context, request modelgateway.NormalizedRequest, _ modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error) {
	gateway.requests = append(gateway.requests, request)
	if len(gateway.requests) > len(gateway.responses) {
		return modelgateway.NormalizedResponse{}, errors.New("unexpected model call")
	}
	return gateway.responses[len(gateway.requests)-1], nil
}

type runtimeToolScopes struct{}

func (runtimeToolScopes) ResolveExecutionScope(context.Context, string, string, string) (toolbroker.ExecutionScope, error) {
	return toolbroker.ExecutionScope{ProjectVersion: 7, TaskVersion: 9, SpecDigest: testScope().Task.SpecDigest}, nil
}

type runtimeToolPolicy struct{}

func (runtimeToolPolicy) Evaluate(context.Context, toolbroker.ToolDescriptor, toolbroker.ToolRequest) (toolbroker.PolicyDecision, error) {
	return toolbroker.PolicyDecision{Allow: true, PolicyVersion: leasePolicyVersion}, nil
}

type runtimeToolExecutor struct {
	authorization toolbroker.LeaseValidation
	found         bool
}

func (executor *runtimeToolExecutor) Execute(ctx context.Context, _ toolbroker.ToolDescriptor, _ []byte) ([]byte, error) {
	executor.authorization, executor.found = toolbroker.ExecutionAuthorizationFromContext(ctx)
	return []byte(`{"content":"read result"}`), nil
}

type runtimeToolRecorder struct{}

func (runtimeToolRecorder) Record(context.Context, toolbroker.Invocation) error { return nil }

func runtimeToolDescriptor() toolbroker.ToolDescriptor {
	return toolbroker.ToolDescriptor{
		ToolID: "repository.file.read", Version: "1.0.0", MCPServerID: "aor-repository",
		InputSchemaRef: "urn:aor:repository:file-read:input", OutputSchemaRef: "urn:aor:repository:file-read:output",
		InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object"}`),
		Risk: toolbroker.RiskLow, SideEffect: toolbroker.SideEffectNone, NetworkAccess: toolbroker.NetworkNone,
		FilesystemAccess: toolbroker.FilesystemRead, RequiresApproval: toolbroker.ApprovalNever,
		AllowedRoles: []string{authn.RoleExecutor}, RateLimit: "10/s", TimeoutSeconds: 10, MaxOutputBytes: 1024,
	}
}

func runtimeExecutionDeclaration(lease authz.CapabilityLease, descriptor toolbroker.ToolDescriptor) agentruntime.Declaration {
	bundle := agentruntime.PromptBundle{
		BundleID: "prompt_execution", Version: "1.0.0", Role: agentruntime.RoleExecutor,
		GlobalSafety: "follow policy", RolePrompt: "execute the assigned module",
		FixedWorkflow: "use declared tools", OutputRules: "return structured output",
	}
	bundle.SHA256 = agentruntime.DigestPromptBundle(bundle)
	goalRef := contracts.SpecRef{Version: 1, SHA256: agentruntime.DigestContextContent("goal")}
	planRef := contracts.SpecRef{Version: 1, SHA256: agentruntime.DigestContextContent("plan")}
	moduleRef := contracts.SpecRef{Version: 1, SHA256: agentruntime.DigestContextContent("module")}
	items := []agentruntime.ContextItem{
		runtimeReferenceItem("goal", agentruntime.ContextGoalReference, "artifact://goal", goalRef.SHA256, "goal"),
		runtimeReferenceItem("plan", agentruntime.ContextPlanReference, "artifact://plan", planRef.SHA256, "plan"),
		runtimeReferenceItem("module", agentruntime.ContextModuleReference, "artifact://module", moduleRef.SHA256, "module"),
	}
	manifest := agentruntime.ContextManifest{ManifestID: "context_execution", Version: "1", Role: agentruntime.RoleExecutor, Items: items}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	tool := modelgateway.ToolDefinition{Name: descriptor.ToolID, Version: descriptor.Version, Description: "read a repository file", Schema: append(json.RawMessage(nil), descriptor.InputSchema...)}
	declaration := agentruntime.Declaration{
		RunID: "run_execution", TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID,
		AgentInstanceID: lease.AgentInstanceID, Role: agentruntime.RoleExecutor,
		PromptBundle: bundle, ContextManifest: manifest, ResponseSchemaRef: "urn:aor:execution:result",
		ResponseSchema: json.RawMessage(`{"type":"object"}`), Tools: []modelgateway.ToolDefinition{tool},
		ResponseSemanticValidator: func(json.RawMessage) error { return nil },
		PolicyVersion:             lease.PolicyVersion, PolicyDigest: agentruntime.DigestContextContent("policy"), DataClassification: "INTERNAL",
	}
	declaration.ToolSchemaDigest = agentruntime.DigestToolDefinitions(declaration.Tools)
	declaration.Envelope = aop.Envelope{
		AOPVersion: aop.Version, MessageID: "message_execution", IdempotencyKey: "execution_envelope",
		CorrelationID: "correlation_execution", ProjectID: lease.ProjectID,
		GoalSpec: &goalRef, PlanSpec: &planRef, ModuleSpec: &moduleRef, TaskID: lease.TaskID,
		Sender: aop.Sender{AgentInstanceID: "agent_scheduler", Role: "PLAN_SUPERVISOR", LeaseID: "lease_scheduler"},
		Scope:  aop.ScopeTask, Intent: aop.IntentAssignModule, ExpectedAggregateVersion: 9,
		ArtifactRefs: []string{}, KnowledgeRefs: []string{},
		TraceContext: &aop.TraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
		CreatedAt:    lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
	}
	return declaration
}

func runtimeReferenceItem(id string, kind agentruntime.ContextKind, reference, sourceDigest, content string) agentruntime.ContextItem {
	return agentruntime.ContextItem{
		ID: id, Kind: kind, Reference: reference, SHA256: agentruntime.DigestContextContent(content),
		SourceSHA256: sourceDigest, Trust: agentruntime.TrustProjectApproved, Content: content,
	}
}
