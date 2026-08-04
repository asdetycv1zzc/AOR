package agentruntime

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestRuntimeUsesOnlyGatewayAndBrokerBoundaries(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	authority := &fakeAuthority{clock: clock}
	gateway := &fakeGateway{response: modelgateway.NormalizedResponse{RequestID: "req_model", ModelVersion: "actual-v1", Content: json.RawMessage(`{"intent":"SUBMIT_IMPLEMENTATION"}`)}}
	broker := &fakeBroker{result: toolbroker.ToolResult{InvocationID: "inv_test", Output: []byte(`{"ok":true}`), TrustLevel: "UNTRUSTED"}}
	runtime := newTestRuntime(t, clock, authority, gateway, broker)
	declaration := testDeclaration(RoleExecutor)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))

	response, err := runtime.Generate(context.Background(), declaration.RunID, ModelCall{
		RequestID: "req_model", Provider: "provider", Model: "model", ReservationID: "res_model", MaxOutputTokens: 128,
		ProviderPolicy: "default", CachePolicy: "local", MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if response.ModelVersion != "actual-v1" {
		t.Fatalf("model version = %s", response.ModelVersion)
	}
	request, options := gateway.Captured()
	if request.TenantID != declaration.TenantID || request.AgentInstanceID != declaration.AgentInstanceID || request.PromptDigest == "" || request.PromptBundleVersion != declaration.PromptBundle.Version {
		t.Fatalf("gateway request binding = %#v", request)
	}
	if options.AccountID != "budget_test" || options.ReservationID != "res_model" {
		t.Fatalf("gateway options = %#v", options)
	}
	if snapshot := runtime.slots.(*SlotPool).Snapshot(); snapshot.Active != 0 {
		t.Fatalf("model slot leaked: %#v", snapshot)
	}

	toolResult, err := runtime.InvokeTool(context.Background(), declaration.RunID, ToolCall{RequestID: "req_tool", ToolID: "repo.read", Version: "1", Parameters: json.RawMessage(`{"path":"README.md"}`)})
	if err != nil {
		t.Fatalf("invoke tool: %v", err)
	}
	if toolResult.TrustLevel != "UNTRUSTED" {
		t.Fatalf("tool trust = %s", toolResult.TrustLevel)
	}
	toolRequest := broker.Captured()
	if toolRequest.TenantID != declaration.TenantID || toolRequest.Principal.ID != declaration.AgentInstanceID || toolRequest.Lease.ID != "lease_test" || toolRequest.Lease.FencingToken != 1 || toolRequest.PolicyVersion != "policy_v1" {
		t.Fatalf("broker request binding = %#v", toolRequest)
	}
	snapshot, err := runtime.Snapshot(declaration.RunID)
	if err != nil || snapshot.State != StateRunning || snapshot.Busy {
		t.Fatalf("post-tool snapshot = %#v error=%v", snapshot, err)
	}

	accepted, err := runtime.Complete(context.Background(), declaration.RunID, AgentOutput{Intent: "SUBMIT_IMPLEMENTATION", Payload: json.RawMessage(`{"commit":"0123456789abcdef"}`)})
	if err != nil {
		t.Fatalf("complete role output: %v", err)
	}
	if accepted.PromptDigest != snapshot.PromptDigest || accepted.ContextDigest != snapshot.ContextDigest || accepted.OutputSHA256 == "" || accepted.FencingToken != 1 ||
		accepted.MessageID != declaration.Envelope.MessageID || accepted.CorrelationID != declaration.Envelope.CorrelationID {
		t.Fatalf("accepted result binding = %#v", accepted)
	}
	final, _ := runtime.Snapshot(declaration.RunID)
	if final.State != StateCompleted {
		t.Fatalf("runtime completion state = %s", final.State)
	}
}

func TestExecutorCannotIssueModuleCompletionVerdict(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, &fakeGateway{}, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))
	_, err := runtime.Complete(context.Background(), declaration.RunID, AgentOutput{Intent: "REPORT_MODULE_COMPLETE", Payload: json.RawMessage(`{"status":"complete"}`)})
	if !errors.Is(err, ErrIntentDenied) {
		t.Fatalf("completion verdict error = %v", err)
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateRunning {
		t.Fatalf("denied verdict changed state to %s", snapshot.State)
	}
}

func TestCompleteRevalidatesStructuredOutputSchema(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, &fakeGateway{}, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	declaration.ResponseSchema = json.RawMessage(`{"type":"object","required":["intent","payload"],"properties":{"intent":{"const":"SUBMIT_IMPLEMENTATION"},"payload":{"type":"object","required":["commit"]}}}`)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))
	_, err := runtime.Complete(context.Background(), declaration.RunID, AgentOutput{Intent: aop.IntentSubmitImplementation, Payload: json.RawMessage(`{"wrong":true}`)})
	if !errors.Is(err, ErrOutputInvalid) {
		t.Fatalf("schema-invalid output error = %v", err)
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateRunning {
		t.Fatalf("schema rejection changed state to %s", snapshot.State)
	}
}

func TestDeclarationRejectsExpiredAndMismatchedAOPEnvelope(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, &fakeGateway{}, &fakeBroker{})
	expired := testDeclaration(RoleExecutor)
	expired.Envelope.ExpiresAt = clock.Now()
	if err := runtime.Declare(expired); !errors.Is(err, ErrInvalidDeclaration) {
		t.Fatalf("expired envelope error = %v", err)
	}
	mismatched := testDeclaration(RoleExecutor)
	mismatched.Envelope.ProjectID = "project_other"
	if err := runtime.Declare(mismatched); !errors.Is(err, ErrInvalidDeclaration) {
		t.Fatalf("mismatched envelope error = %v", err)
	}
	substituted := testDeclaration(RoleExecutor)
	substituted.Envelope.ModuleSpec.SHA256 = DigestContextContent("different-module")
	if err := runtime.Declare(substituted); !errors.Is(err, ErrInvalidDeclaration) {
		t.Fatalf("substituted context error = %v", err)
	}
}

func TestModulePlannerDeclarationPrecedesModuleSpec(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, &fakeGateway{}, &fakeBroker{})
	declaration := testDeclaration(RoleModulePlanner)
	declaration.Envelope.Intent = aop.IntentDefineModule
	declaration.Envelope.ModuleSpec = nil
	items := declaration.ContextManifest.Items[:0]
	for _, item := range declaration.ContextManifest.Items {
		if item.Kind != ContextModuleReference {
			items = append(items, item)
		}
	}
	declaration.ContextManifest.Items = items
	declaration.ContextManifest.SHA256 = DigestContextManifest(declaration.ContextManifest)
	if err := runtime.Declare(declaration); err != nil {
		t.Fatalf("pre-ModuleSpec declaration rejected: %v", err)
	}
}

func TestExpiredLeaseRejectsProviderResult(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	authority := &fakeAuthority{clock: clock}
	gateway := &fakeGateway{response: modelgateway.NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}, callback: func() { clock.Advance(91 * time.Second) }}
	runtime := newTestRuntime(t, clock, authority, gateway, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	lease := testLease(clock.Now(), declaration)
	lease.LastHeartbeatAt = clock.Now()
	startRun(t, runtime, declaration, lease)
	_, err := runtime.Generate(context.Background(), declaration.RunID, ModelCall{RequestID: "req", Provider: "provider", Model: "model", ReservationID: "res", MaxOutputTokens: 16, ProviderPolicy: "default", CachePolicy: "none"})
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired result error = %v", err)
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateExpired {
		t.Fatalf("expired run state = %s", snapshot.State)
	}
}

func TestStartAuthorizationFailureReturnsToLeased(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	authority := &fakeAuthority{clock: clock}
	runtime := newTestRuntime(t, clock, authority, &fakeGateway{}, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	if err := runtime.Declare(declaration); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := runtime.Queue(declaration.RunID); err != nil {
		t.Fatalf("queue: %v", err)
	}
	lease := testLease(clock.Now(), declaration)
	if err := runtime.AssignLease(context.Background(), declaration.RunID, lease); err != nil {
		t.Fatalf("assign lease: %v", err)
	}
	authority.mu.Lock()
	authority.reject = true
	authority.mu.Unlock()
	if err := runtime.Start(context.Background(), declaration.RunID); err == nil {
		t.Fatal("start unexpectedly allowed")
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateLeased {
		t.Fatalf("failed start state = %s", snapshot.State)
	}
}

func TestCompleteRejectsLeaseExpiryAtCommitBoundary(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	authority := &fakeAuthority{clock: clock}
	authority.onValidate = func(operation LeaseOperation) {
		if operation == LeaseOperationResult {
			clock.Advance(91 * time.Second)
		}
	}
	runtime := newTestRuntime(t, clock, authority, &fakeGateway{}, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))
	_, err := runtime.Complete(context.Background(), declaration.RunID, AgentOutput{Intent: aop.IntentSubmitImplementation, Payload: json.RawMessage(`{"commit":"0123456789abcdef"}`)})
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("commit expiry error = %v", err)
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateExpired {
		t.Fatalf("commit expiry state = %s", snapshot.State)
	}
}

func TestCancelPropagatesToActiveModelCall(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	entered := make(chan struct{})
	gateway := &fakeGateway{generate: func(ctx context.Context) (modelgateway.NormalizedResponse, error) {
		close(entered)
		<-ctx.Done()
		return modelgateway.NormalizedResponse{}, ctx.Err()
	}}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, gateway, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))
	result := make(chan error, 1)
	go func() {
		_, err := runtime.Generate(context.Background(), declaration.RunID, ModelCall{RequestID: "req", Provider: "provider", Model: "model", ReservationID: "res", MaxOutputTokens: 16, ProviderPolicy: "default", CachePolicy: "none"})
		result <- err
	}()
	<-entered
	if err := runtime.Cancel(declaration.RunID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("generate cancellation error = %v", err)
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateCanceled || snapshot.Busy {
		t.Fatalf("canceled snapshot = %#v", snapshot)
	}
	if active := runtime.slots.(*SlotPool).Snapshot().Active; active != 0 {
		t.Fatalf("active slots after cancel = %d", active)
	}
}

func TestLongModelCallUsesLatestHeartbeat(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	entered := make(chan struct{})
	proceed := make(chan struct{})
	gateway := &fakeGateway{generate: func(context.Context) (modelgateway.NormalizedResponse, error) {
		close(entered)
		<-proceed
		return modelgateway.NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}, nil
	}}
	authority := &fakeAuthority{clock: clock}
	runtime := newTestRuntime(t, clock, authority, gateway, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))
	result := make(chan error, 1)
	go func() {
		_, err := runtime.Generate(context.Background(), declaration.RunID, ModelCall{RequestID: "req", Provider: "provider", Model: "model", ReservationID: "res", MaxOutputTokens: 16, ProviderPolicy: "default", CachePolicy: "none"})
		result <- err
	}()
	<-entered
	clock.Advance(80 * time.Second)
	if err := runtime.Heartbeat(context.Background(), declaration.RunID); err != nil {
		t.Fatalf("heartbeat during model call: %v", err)
	}
	clock.Advance(20 * time.Second)
	close(proceed)
	if err := <-result; err != nil {
		t.Fatalf("fresh heartbeat rejected model result: %v", err)
	}
	snapshot, _ := runtime.Snapshot(declaration.RunID)
	if snapshot.State != StateRunning || snapshot.Busy {
		t.Fatalf("post-call snapshot = %#v", snapshot)
	}
}

func TestLeaseIsRevalidatedAfterWaitingForGlobalSlot(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	gateway := &fakeGateway{response: modelgateway.NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, gateway, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	lease := testLease(clock.Now(), declaration)
	lease.LastHeartbeatAt = clock.Now()
	startRun(t, runtime, declaration, lease)
	pool := runtime.slots.(*SlotPool)
	releases := make([]func(), 0, MaximumActiveAgentLimit)
	for index := 0; index < MaximumActiveAgentLimit; index++ {
		release, err := pool.Acquire(context.Background(), RoleExecutor, 1)
		if err != nil {
			t.Fatalf("fill slot %d: %v", index, err)
		}
		releases = append(releases, release)
	}
	result := make(chan error, 1)
	go func() {
		_, err := runtime.Generate(context.Background(), declaration.RunID, ModelCall{RequestID: "req", Provider: "provider", Model: "model", ReservationID: "res", MaxOutputTokens: 16, ProviderPolicy: "default", CachePolicy: "none"})
		result <- err
	}()
	waitForWaiting(t, pool, 1)
	clock.Advance(91 * time.Second)
	releases[0]()
	if err := <-result; !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("queued expiry error = %v", err)
	}
	for _, release := range releases {
		release()
	}
	if gateway.Calls() != 0 {
		t.Fatalf("gateway called after queued lease expiry")
	}
}

func TestLeaseBindingHeartbeatAndMissedHeartbeat(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	authority := &fakeAuthority{clock: clock}
	runtime := newTestRuntime(t, clock, authority, &fakeGateway{}, &fakeBroker{})
	declaration := testDeclaration(RoleExecutor)
	if err := runtime.Declare(declaration); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := runtime.Queue(declaration.RunID); err != nil {
		t.Fatalf("queue: %v", err)
	}
	wrong := testLease(clock.Now(), declaration)
	wrong.ProjectID = "project_other"
	if err := runtime.AssignLease(context.Background(), declaration.RunID, wrong); !errors.Is(err, ErrLeaseBinding) {
		t.Fatalf("wrong binding error = %v", err)
	}
	wrongPolicy := testLease(clock.Now(), declaration)
	wrongPolicy.PolicyVersion = "policy_other"
	if err := runtime.AssignLease(context.Background(), declaration.RunID, wrongPolicy); !errors.Is(err, ErrLeaseBinding) {
		t.Fatalf("wrong policy binding error = %v", err)
	}
	lease := testLease(clock.Now(), declaration)
	if err := runtime.AssignLease(context.Background(), declaration.RunID, lease); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := runtime.Start(context.Background(), declaration.RunID); err != nil {
		t.Fatalf("start: %v", err)
	}
	clock.Advance(10 * time.Second)
	if err := runtime.Heartbeat(context.Background(), declaration.RunID); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	clock.Advance(90 * time.Second)
	expired := runtime.ExpireStale()
	if len(expired) != 1 || expired[0] != declaration.RunID {
		t.Fatalf("expired runs = %#v", expired)
	}
}

func newTestRuntime(t *testing.T, clock *mutableClock, authority LeaseAuthority, gateway ModelGateway, broker ToolBroker) *Runtime {
	t.Helper()
	slots, err := NewSlotPool(MaximumActiveAgentLimit, clock.Now)
	if err != nil {
		t.Fatalf("new slots: %v", err)
	}
	runtime, err := New(authority, gateway, broker, slots, clock.Now)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	return runtime
}

func startRun(t *testing.T, runtime *Runtime, declaration Declaration, lease AgentLease) {
	t.Helper()
	if err := runtime.Declare(declaration); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := runtime.Queue(declaration.RunID); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if err := runtime.AssignLease(context.Background(), declaration.RunID, lease); err != nil {
		t.Fatalf("assign lease: %v", err)
	}
	if err := runtime.Start(context.Background(), declaration.RunID); err != nil {
		t.Fatalf("start: %v", err)
	}
}

func testDeclaration(role Role) Declaration {
	bundle := testPromptBundle(role)
	items := []ContextItem{
		testContextItem("goal", ContextGoalReference, "artifact://goal", TrustProjectApproved, "goal"),
		testContextItem("plan", ContextPlanReference, "artifact://plan", TrustProjectApproved, "plan"),
		testContextItem("module", ContextModuleReference, "artifact://module", TrustProjectApproved, "module"),
	}
	if role == RoleModulePlanner {
		items = append(items, testContextItem("assignment", ContextTaskState, "aor://task/task_test", TrustGeneratedUnreviewed, "planned module assignment"))
	}
	manifest := testManifest(role, items)
	tool := modelgateway.ToolDefinition{Name: "repo.read", Description: "read one repository file", Schema: json.RawMessage(`{"type":"object"}`)}
	declaration := Declaration{
		RunID: "run_test", TenantID: "tenant_test", ProjectID: "project_test", AgentInstanceID: "agent_test", Role: role,
		PromptBundle: bundle, ContextManifest: manifest, ResponseSchemaRef: "schema://agent-output",
		ResponseSchema: json.RawMessage(`{"type":"object"}`), Tools: []modelgateway.ToolDefinition{tool},
		PolicyVersion: "policy_v1", PolicyDigest: DigestContextContent("policy"), DataClassification: "INTERNAL",
	}
	if roleRequiresTask(role) {
		declaration.TaskID = "task_test"
	}
	goalRef := &contracts.SpecRef{Version: 1, SHA256: DigestContextContent("goal")}
	planRef := &contracts.SpecRef{Version: 1, SHA256: DigestContextContent("plan")}
	moduleRef := &contracts.SpecRef{Version: 1, SHA256: DigestContextContent("module")}
	envelope := aop.Envelope{
		AOPVersion: aop.Version, MessageID: "msg_test", IdempotencyKey: "idem_test", CorrelationID: "corr_test",
		ProjectID: declaration.ProjectID, GoalSpec: goalRef,
		Sender:                   aop.Sender{AgentInstanceID: "agent_scheduler", Role: "PLAN_SUPERVISOR", LeaseID: "lease_scheduler"},
		ExpectedAggregateVersion: 7, ArtifactRefs: []string{}, KnowledgeRefs: []string{},
		TraceContext: &aop.TraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
		CreatedAt:    time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
	}
	switch role {
	case RoleModulePlanner, RoleExecutor, RoleModuleAuditor:
		envelope.Intent = aop.IntentAssignModule
		envelope.Scope = aop.ScopeTask
		envelope.PlanSpec = planRef
		envelope.ModuleSpec = moduleRef
		envelope.TaskID = declaration.TaskID
	case RoleGlobalAuditor:
		envelope.Intent = aop.IntentRequestGlobalAudit
		envelope.Scope = aop.ScopeProject
		envelope.PlanSpec = planRef
	default:
		envelope.Intent = aop.IntentRequestAgent
		envelope.Scope = aop.ScopeProject
	}
	declaration.Envelope = envelope
	declaration.ToolSchemaDigest = DigestToolDefinitions(declaration.Tools)
	return declaration
}

func testLease(now time.Time, declaration Declaration) AgentLease {
	return AgentLease{
		LeaseID: "lease_test", AgentInstanceID: declaration.AgentInstanceID, TenantID: declaration.TenantID,
		ProjectID: declaration.ProjectID, TaskID: declaration.TaskID, Role: declaration.Role,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute), LastHeartbeatAt: now.Add(-time.Second),
		HeartbeatIntervalSeconds: DefaultHeartbeatSeconds, Capabilities: []string{"model.generate", "tool.invoke"},
		PolicyVersion: "policy_v1", BudgetAccountID: "budget_test", Nonce: "nonce_test", FencingToken: 1, Signature: "signature_test",
	}
}

type fakeAuthority struct {
	clock      *mutableClock
	mu         sync.Mutex
	reject     bool
	calls      []LeaseOperation
	onValidate func(LeaseOperation)
}

func (a *fakeAuthority) Validate(_ context.Context, _ AgentLease, operation LeaseOperation) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, operation)
	if a.onValidate != nil {
		a.onValidate(operation)
	}
	if a.reject {
		return errors.New("denied")
	}
	return nil
}

func (a *fakeAuthority) Heartbeat(_ context.Context, lease AgentLease) (AgentLease, error) {
	if a.reject {
		return AgentLease{}, errors.New("denied")
	}
	lease.LastHeartbeatAt = a.clock.Now()
	lease.Signature = "heartbeat_signature"
	return lease, nil
}

func (a *fakeAuthority) Renew(_ context.Context, lease AgentLease) (AgentLease, error) {
	if a.reject {
		return AgentLease{}, errors.New("denied")
	}
	lease.LastHeartbeatAt = a.clock.Now()
	lease.ExpiresAt = lease.ExpiresAt.Add(10 * time.Minute)
	lease.FencingToken++
	lease.Signature = "renewed_signature"
	return lease, nil
}

type fakeGateway struct {
	mu       sync.Mutex
	request  modelgateway.NormalizedRequest
	options  modelgateway.GenerateOptions
	response modelgateway.NormalizedResponse
	err      error
	callback func()
	generate func(context.Context) (modelgateway.NormalizedResponse, error)
	calls    int
}

func (g *fakeGateway) Generate(ctx context.Context, request modelgateway.NormalizedRequest, options modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error) {
	g.mu.Lock()
	g.calls++
	g.request = request
	g.options = options
	generate := g.generate
	callback := g.callback
	response := g.response
	err := g.err
	g.mu.Unlock()
	if callback != nil {
		callback()
	}
	if generate != nil {
		return generate(ctx)
	}
	return response, err
}

func (g *fakeGateway) Calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func (g *fakeGateway) Captured() (modelgateway.NormalizedRequest, modelgateway.GenerateOptions) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.request, g.options
}

type fakeBroker struct {
	mu      sync.Mutex
	request toolbroker.ToolRequest
	result  toolbroker.ToolResult
	err     error
}

func (b *fakeBroker) Invoke(_ context.Context, request toolbroker.ToolRequest) (toolbroker.ToolResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.request = request
	return b.result, b.err
}

func (b *fakeBroker) Captured() toolbroker.ToolRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.request
}
