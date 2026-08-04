package goalplan

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/prompts"
)

func TestRuntimeAgentInvokerExecutesAndReplaysCompletedRun(t *testing.T) {
	now := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	gateway := &runtimeInvokerGateway{response: modelgateway.NormalizedResponse{RequestID: "request_goal", Content: json.RawMessage(`{"ok":true}`)}}
	runtime := newGoalPlanRuntime(t, now, gateway, &runtimeInvokerAuthority{})
	prepared := initialGoalRuntimeInvocation(t, now)
	invoker, err := NewRuntimeAgentInvoker(runtime, runtimeInvocationPreparerFunc(func(context.Context, AgentInvocation) (RuntimeInvocation, error) {
		return prepared, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := AgentInvocation{InvocationID: "run_goal", TenantID: "tenant_goal", ProjectID: "project_goal", Role: agentruntime.RoleGoalProposer, Stage: "GOAL_DRAFT"}

	first, err := invoker.Invoke(context.Background(), request)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	second, err := invoker.Invoke(context.Background(), request)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if first.RunID != "run_goal" || first.AgentInstanceID != "agent_goal" || first.Role != agentruntime.RoleGoalProposer || string(first.Payload) != `{"ok":true}` {
		t.Fatalf("unexpected record: %#v", first)
	}
	if string(second.Payload) != string(first.Payload) || gateway.Calls() != 1 {
		t.Fatalf("replay invoked provider: second=%#v calls=%d", second, gateway.Calls())
	}
}

func TestRuntimeAgentInvokerFailsClosedOnPreparationMismatch(t *testing.T) {
	now := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	gateway := &runtimeInvokerGateway{response: modelgateway.NormalizedResponse{RequestID: "request_goal", Content: json.RawMessage(`{"ok":true}`)}}
	runtime := newGoalPlanRuntime(t, now, gateway, &runtimeInvokerAuthority{})
	prepared := initialGoalRuntimeInvocation(t, now)
	prepared.Intent = aop.IntentChallengeGoal
	invoker, _ := NewRuntimeAgentInvoker(runtime, runtimeInvocationPreparerFunc(func(context.Context, AgentInvocation) (RuntimeInvocation, error) {
		return prepared, nil
	}))
	request := AgentInvocation{InvocationID: "run_goal", TenantID: "tenant_goal", ProjectID: "project_goal", Role: agentruntime.RoleGoalProposer, Stage: "GOAL_DRAFT"}

	if _, err := invoker.Invoke(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatched intent error = %v", err)
	}
	if gateway.Calls() != 0 {
		t.Fatalf("provider called after invalid preparation: %d", gateway.Calls())
	}
}

func TestRuntimeAgentInvokerRejectsInvalidStructuredOutput(t *testing.T) {
	now := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	gateway := &runtimeInvokerGateway{response: modelgateway.NormalizedResponse{RequestID: "request_goal", Content: json.RawMessage(`{"wrong":true}`)}}
	runtime := newGoalPlanRuntime(t, now, gateway, &runtimeInvokerAuthority{})
	prepared := initialGoalRuntimeInvocation(t, now)
	invoker, _ := NewRuntimeAgentInvoker(runtime, runtimeInvocationPreparerFunc(func(context.Context, AgentInvocation) (RuntimeInvocation, error) {
		return prepared, nil
	}))
	request := AgentInvocation{InvocationID: "run_goal", TenantID: "tenant_goal", ProjectID: "project_goal", Role: agentruntime.RoleGoalProposer, Stage: "GOAL_DRAFT"}

	if _, err := invoker.Invoke(context.Background(), request); !errors.Is(err, agentruntime.ErrOutputInvalid) {
		t.Fatalf("invalid model output error = %v", err)
	}
	snapshot, err := runtime.Snapshot("run_goal")
	if err != nil || snapshot.State != agentruntime.StateFailed {
		t.Fatalf("failed run snapshot = %#v, %v", snapshot, err)
	}
}

func TestInitialGoalRuntimeRequiresUserInputContext(t *testing.T) {
	now := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	prepared := initialGoalRuntimeInvocation(t, now)
	prepared.Declaration.ContextManifest.Items = nil
	prepared.Declaration.ContextManifest.SHA256 = agentruntime.DigestContextManifest(prepared.Declaration.ContextManifest)
	runtime := newGoalPlanRuntime(t, now, &runtimeInvokerGateway{}, &runtimeInvokerAuthority{})
	invoker, _ := NewRuntimeAgentInvoker(runtime, runtimeInvocationPreparerFunc(func(context.Context, AgentInvocation) (RuntimeInvocation, error) {
		return prepared, nil
	}))
	request := AgentInvocation{InvocationID: "run_goal", TenantID: "tenant_goal", ProjectID: "project_goal", Role: agentruntime.RoleGoalProposer, Stage: "GOAL_DRAFT"}

	if _, err := invoker.Invoke(context.Background(), request); !errors.Is(err, agentruntime.ErrInvalidDeclaration) {
		t.Fatalf("missing user input error = %v", err)
	}
}

func initialGoalRuntimeInvocation(t *testing.T, now time.Time) RuntimeInvocation {
	t.Helper()
	bundle, err := prompts.LoadBaseline(agentruntime.RoleGoalProposer)
	if err != nil {
		t.Fatal(err)
	}
	userContent := "Create an auditable service"
	item := agentruntime.ContextItem{
		ID: "input_goal", Kind: agentruntime.ContextUserInput, Reference: "artifact://sha256/user-message",
		SHA256: agentruntime.DigestContextContent(userContent), Trust: agentruntime.TrustExternalUntrusted, Content: userContent,
	}
	manifest := agentruntime.ContextManifest{ManifestID: "context_goal", Version: "1", Role: agentruntime.RoleGoalProposer, Items: []agentruntime.ContextItem{item}}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	responseSchema := json.RawMessage(`{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}},"additionalProperties":false}`)
	declaration := agentruntime.Declaration{
		RunID: "run_goal", TenantID: "tenant_goal", ProjectID: "project_goal", AgentInstanceID: "agent_goal", Role: agentruntime.RoleGoalProposer,
		PromptBundle: bundle, ContextManifest: manifest, ResponseSchemaRef: "schema://goal-draft", ResponseSchema: responseSchema,
		ToolSchemaDigest: agentruntime.DigestToolDefinitions(nil), PolicyVersion: "policy_v1", PolicyDigest: agentruntime.DigestContextContent("policy_v1"), DataClassification: "INTERNAL",
		Envelope: aop.Envelope{
			AOPVersion: aop.Version, MessageID: "message_goal", IdempotencyKey: "idempotency_goal", CorrelationID: "correlation_goal",
			ProjectID: "project_goal", Sender: aop.Sender{AgentInstanceID: "scheduler_goal", Role: "SERVICE", LeaseID: "lease_scheduler"},
			Scope: aop.ScopeProject, Intent: aop.IntentProposeGoal, ExpectedAggregateVersion: 1, ArtifactRefs: []string{}, KnowledgeRefs: []string{},
			TraceContext: &aop.TraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}, CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		},
	}
	lease := agentruntime.AgentLease{
		LeaseID: "lease_goal", AgentInstanceID: "agent_goal", TenantID: "tenant_goal", ProjectID: "project_goal", Role: agentruntime.RoleGoalProposer,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(5 * time.Minute), LastHeartbeatAt: now,
		HeartbeatIntervalSeconds: agentruntime.DefaultHeartbeatSeconds, Capabilities: []string{"model.generate"}, PolicyVersion: "policy_v1",
		BudgetAccountID: "budget_goal", Nonce: "nonce_goal", FencingToken: 1, Signature: "signature_goal",
	}
	call := agentruntime.ModelCall{
		RequestID: "request_goal", Provider: "provider_goal", Model: "model_goal", ReservationID: "reservation_goal",
		MaxOutputTokens: 1024, Temperature: 0, ProviderPolicy: "default", CachePolicy: "NO_STORE", WorstCaseCostMicros: 1000, MaxAttempts: 1,
	}
	return RuntimeInvocation{Declaration: declaration, Lease: lease, ModelCall: call, Intent: aop.IntentProposeGoal}
}

func newGoalPlanRuntime(t *testing.T, now time.Time, gateway agentruntime.ModelGateway, authority agentruntime.LeaseAuthority) *agentruntime.Runtime {
	t.Helper()
	slots, err := agentruntime.NewSlotPool(agentruntime.MaximumActiveAgentLimit, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := agentruntime.New(authority, gateway, nil, slots, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

type runtimeInvocationPreparerFunc func(context.Context, AgentInvocation) (RuntimeInvocation, error)

func (function runtimeInvocationPreparerFunc) Prepare(ctx context.Context, request AgentInvocation) (RuntimeInvocation, error) {
	return function(ctx, request)
}

type runtimeInvokerGateway struct {
	mu       sync.Mutex
	response modelgateway.NormalizedResponse
	err      error
	calls    int
}

func (gateway *runtimeInvokerGateway) Generate(context.Context, modelgateway.NormalizedRequest, modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error) {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	gateway.calls++
	return gateway.response, gateway.err
}

func (gateway *runtimeInvokerGateway) Calls() int {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	return gateway.calls
}

type runtimeInvokerAuthority struct {
	err error
}

func (authority *runtimeInvokerAuthority) Validate(context.Context, agentruntime.AgentLease, agentruntime.LeaseOperation) error {
	return authority.err
}

func (authority *runtimeInvokerAuthority) Heartbeat(_ context.Context, lease agentruntime.AgentLease) (agentruntime.AgentLease, error) {
	return lease, authority.err
}

func (authority *runtimeInvokerAuthority) Renew(_ context.Context, lease agentruntime.AgentLease) (agentruntime.AgentLease, error) {
	return lease, authority.err
}
