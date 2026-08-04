package toolbroker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

var brokerTestNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

type testLease struct {
	validations    []LeaseValidation
	expectedDigest string
	failAt         int
}

type concurrentLease struct{}

func (concurrentLease) Validate(context.Context, LeaseValidation) error { return nil }

type concurrentExecutor struct {
	calls atomic.Int64
	gate  chan struct{}
}

func (executor *concurrentExecutor) Execute(ctx context.Context, _ ToolDescriptor, _ []byte) ([]byte, error) {
	executor.calls.Add(1)
	if executor.gate != nil {
		select {
		case <-executor.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []byte(`{"ok":true}`), nil
}

type concurrentRecorder struct{ calls atomic.Int64 }

func (recorder *concurrentRecorder) Record(context.Context, Invocation) error {
	recorder.calls.Add(1)
	return nil
}

func (l *testLease) Validate(_ context.Context, validation LeaseValidation) error {
	l.validations = append(l.validations, validation)
	if validation.Lease.ID == "" || validation.Lease.FencingToken < 1 || validation.Principal.ID == "" || validation.Principal.Type == "" || validation.Principal.Role == "" || validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" || validation.ToolID == "" || validation.ToolVersion == "" || validation.MCPServerID == "" || validation.Action != "tool.invoke" || validation.Resource == "" || validation.ParameterSHA256 == "" || validation.PolicyVersion == "" || validation.BudgetAccountID == "" || validation.At.IsZero() {
		return ErrLeaseInvalid
	}
	if l.expectedDigest != "" && validation.ParameterSHA256 != l.expectedDigest || l.failAt > 0 && len(l.validations) >= l.failAt {
		return ErrLeaseInvalid
	}
	return nil
}

type testPolicy struct{}

func (testPolicy) Evaluate(context.Context, ToolDescriptor, ToolRequest) (PolicyDecision, error) {
	return PolicyDecision{Allow: true, PolicyVersion: "policy-1"}, nil
}

type testExecutor struct {
	output []byte
	calls  int
}

type authorizationCapturingExecutor struct {
	validation LeaseValidation
	requestID  string
	found      bool
}

func (executor *authorizationCapturingExecutor) Execute(ctx context.Context, _ ToolDescriptor, _ []byte) ([]byte, error) {
	executor.validation, executor.found = ExecutionAuthorizationFromContext(ctx)
	executor.requestID, _ = InvocationRequestIDFromContext(ctx)
	return []byte(`{"ok":true}`), nil
}

func (e *testExecutor) Execute(context.Context, ToolDescriptor, []byte) ([]byte, error) {
	e.calls++
	return append([]byte(nil), e.output...), nil
}

type testRecorder struct{ calls int }

func (r *testRecorder) Record(context.Context, Invocation) error { r.calls++; return nil }

type testArtifacts struct {
	called    bool
	mediaType string
	request   ToolRequest
}

func (a *testArtifacts) Put(_ context.Context, request ToolRequest, data []byte, mediaType string) (ArtifactRef, error) {
	a.called = true
	a.mediaType = mediaType
	a.request = request
	return ArtifactRef{URI: "artifact://out", SHA256: "sha256:out", Size: int64(len(data))}, nil
}

func descriptor() ToolDescriptor {
	return ToolDescriptor{ToolID: "repo.read", Version: "1.0.0", MCPServerID: "repo", InputSchemaRef: "urn:in", OutputSchemaRef: "urn:out", InputSchema: []byte(`{"type":"object"}`), OutputSchema: []byte(`{"type":"object"}`), Risk: RiskLow, SideEffect: SideEffectNone, NetworkAccess: NetworkNone, FilesystemAccess: FilesystemRead, RequiresApproval: ApprovalNever, AllowedRoles: []string{"EXECUTOR"}, RateLimit: "10/s", TimeoutSeconds: 10, MaxOutputBytes: 100}
}

func request() ToolRequest {
	return ToolRequest{RequestID: "req", TenantID: "ten", ProjectID: "prj", TaskID: "task", Principal: Principal{ID: "agt", Type: "AGENT_INSTANCE", Role: "EXECUTOR"}, Lease: Lease{ID: "lease", ExpiresAt: brokerTestNow.Add(time.Hour).Format(time.RFC3339), FencingToken: 1}, ToolID: "repo.read", Version: "1.0.0", Parameters: []byte(`{}`), PolicyVersion: "policy-1", BudgetAccountID: "budget-1"}
}

func TestBrokerStableListAndInvocation(t *testing.T) {
	executor := &testExecutor{output: []byte(`{"ok":true}`)}
	recorder := &testRecorder{}
	lease := &testLease{}
	broker := New(lease, testPolicy{}, executor, nil, recorder, nil, func() time.Time { return brokerTestNow })
	if err := broker.Register(descriptor()); err != nil {
		t.Fatal(err)
	}
	result, err := broker.Invoke(context.Background(), request())
	if err != nil || string(result.Output) != `{"ok":true}` || recorder.calls != 1 || executor.calls != 1 {
		t.Fatalf("result = %#v err=%v", result, err)
	}
	parameterDigest, _ := canonicaljson.Digest([]byte(`{}`))
	if len(lease.validations) != 1 || lease.validations[0].ParameterSHA256 != parameterDigest || lease.validations[0].ToolVersion != "1.0.0" || lease.validations[0].Resource != "tool://repo/repo.read@1.0.0" || !lease.validations[0].At.Equal(brokerTestNow) {
		t.Fatalf("lease validation was not bound to the invocation: %#v", lease.validations)
	}
}

func TestBrokerSuppliesValidatedAuthorizationOnlyDuringExecution(t *testing.T) {
	executor := &authorizationCapturingExecutor{}
	broker := New(&testLease{}, testPolicy{}, executor, nil, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	if err := broker.Register(descriptor()); err != nil {
		t.Fatal(err)
	}
	if _, found := ExecutionAuthorizationFromContext(context.Background()); found {
		t.Fatal("authorization escaped broker execution context")
	}
	if _, err := broker.Invoke(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	if !executor.found || executor.requestID != request().RequestID || executor.validation.Lease.ID != request().Lease.ID || executor.validation.ToolID != request().ToolID || executor.validation.ParameterSHA256 == "" {
		t.Fatalf("execution authorization = %#v found=%t", executor.validation, executor.found)
	}
}

func TestBrokerRejectsIrreversibleCallWithoutRevalidation(t *testing.T) {
	d := descriptor()
	d.SideEffect = SideEffectIrreversible
	broker := New(&testLease{}, testPolicy{}, &testExecutor{output: []byte(`{}`)}, nil, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	_, err := broker.Invoke(context.Background(), request())
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("revalidation error = %v", err)
	}
}

func TestBrokerSpillsLargeOutput(t *testing.T) {
	d := descriptor()
	d.MaxOutputBytes = 10
	artifacts := &testArtifacts{}
	executor := &testExecutor{output: []byte(`{"large":"123456789012345"}`)}
	broker := New(&testLease{}, testPolicy{}, executor, artifacts, &testRecorder{}, func(context.Context, ToolRequest, ToolDescriptor) error { return nil }, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	result, err := broker.Invoke(context.Background(), request())
	if err != nil || result.Artifact == nil || !artifacts.called || artifacts.mediaType != "application/json" || artifacts.request.RequestID != request().RequestID {
		t.Fatalf("artifact result = %#v err=%v", result, err)
	}
}

func TestBrokerValidatesLargeOutputBeforeArtifactPublication(t *testing.T) {
	d := descriptor()
	d.MaxOutputBytes = 10
	d.OutputSchema = []byte(`{"type":"object","required":["ok"]}`)
	artifacts := &testArtifacts{}
	executor := &testExecutor{output: []byte(`{"large":"123456789012345"}`)}
	broker := New(&testLease{}, testPolicy{}, executor, artifacts, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Invoke(context.Background(), request()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("large invalid output error = %v", err)
	}
	if artifacts.called {
		t.Fatal("schema-invalid output was published as an artifact")
	}
}

func TestBrokerRevalidatesExactLeaseBeforeEverySideEffect(t *testing.T) {
	d := descriptor()
	d.ToolID = "repo.update"
	d.SideEffect = SideEffectReversible
	d.FilesystemAccess = FilesystemScopedWrite
	lease := &testLease{failAt: 2}
	executor := &testExecutor{output: []byte(`{}`)}
	broker := New(lease, testPolicy{}, executor, nil, &testRecorder{}, func(context.Context, ToolRequest, ToolDescriptor) error { return nil }, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	changed := request()
	changed.ToolID = d.ToolID
	if _, err := broker.Invoke(context.Background(), changed); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("revoked commit-time lease error = %v", err)
	}
	if len(lease.validations) != 2 || executor.calls != 0 {
		t.Fatalf("side effect ran without second lease validation: validations=%d executions=%d", len(lease.validations), executor.calls)
	}
}

func TestBrokerTreatsScopedFilesystemWritesAsPermanentEffects(t *testing.T) {
	d := descriptor()
	d.ToolID = "repo.inspect"
	d.SideEffect = SideEffectNone
	d.FilesystemAccess = FilesystemScopedWrite
	lease := &testLease{failAt: 2}
	executor := &testExecutor{output: []byte(`{}`)}
	broker := New(lease, testPolicy{}, executor, nil, &testRecorder{}, func(context.Context, ToolRequest, ToolDescriptor) error { return nil }, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	changed := request()
	changed.ToolID = d.ToolID
	if _, err := broker.Invoke(context.Background(), changed); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("scoped write with revoked lease error = %v", err)
	}
	if len(lease.validations) != 2 || executor.calls != 0 {
		t.Fatalf("scoped write bypassed commit-time validation: validations=%d executions=%d", len(lease.validations), executor.calls)
	}
}

func TestBrokerRejectsRevocationBeforePublishingExecutorResult(t *testing.T) {
	d := descriptor()
	d.ToolID = "repo.update"
	d.SideEffect = SideEffectReversible
	d.FilesystemAccess = FilesystemScopedWrite
	d.MaxOutputBytes = 10
	lease := &testLease{failAt: 3}
	executor := &testExecutor{output: []byte(`{"large":"123456789012345"}`)}
	artifacts := &testArtifacts{}
	recorder := &testRecorder{}
	broker := New(lease, testPolicy{}, executor, artifacts, recorder, func(context.Context, ToolRequest, ToolDescriptor) error { return nil }, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	changed := request()
	changed.ToolID = d.ToolID
	if _, err := broker.Invoke(context.Background(), changed); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("post-execution revocation error = %v", err)
	}
	broker.mu.RLock()
	cached := len(broker.cache)
	broker.mu.RUnlock()
	if len(lease.validations) != 3 || executor.calls != 1 || artifacts.called || recorder.calls != 0 || cached != 0 {
		t.Fatalf("revoked result became trusted: validations=%d executions=%d artifact=%t records=%d cache=%d", len(lease.validations), executor.calls, artifacts.called, recorder.calls, cached)
	}
}

func TestBrokerRejectsAuditorWriteToolsAndParameterReplay(t *testing.T) {
	write := descriptor()
	write.ToolID = "repository.write"
	write.SideEffect = SideEffectReversible
	write.FilesystemAccess = FilesystemScopedWrite
	write.AllowedRoles = []string{"GLOBAL_AUDITOR"}
	broker := New(&testLease{}, testPolicy{}, &testExecutor{}, nil, &testRecorder{}, func(context.Context, ToolRequest, ToolDescriptor) error { return nil }, func() time.Time { return brokerTestNow })
	if err := broker.Register(write); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("auditor write descriptor error = %v", err)
	}

	expected, _ := canonicaljson.Digest([]byte(`{"path":"owned/one"}`))
	lease := &testLease{expectedDigest: expected}
	readBroker := New(lease, testPolicy{}, &testExecutor{output: []byte(`{}`)}, nil, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	if err := readBroker.Register(descriptor()); err != nil {
		t.Fatal(err)
	}
	replayed := request()
	replayed.Parameters = []byte(`{"path":"owned/two"}`)
	if _, err := readBroker.Invoke(context.Background(), replayed); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("changed parameter replay error = %v", err)
	}
}

func TestBrokerCoalescesOneHundredConcurrentIdempotentCalls(t *testing.T) {
	executor := &concurrentExecutor{gate: make(chan struct{})}
	recorder := &concurrentRecorder{}
	broker := New(concurrentLease{}, testPolicy{}, executor, nil, recorder, nil, func() time.Time { return brokerTestNow })
	d := descriptor()
	d.RateLimit = "1000/s"
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	const calls = 100
	results := make(chan error, calls)
	var started sync.WaitGroup
	started.Add(calls)
	for range calls {
		go func() {
			started.Done()
			_, err := broker.Invoke(context.Background(), request())
			results <- err
		}()
	}
	started.Wait()
	close(executor.gate)
	for range calls {
		if err := <-results; err != nil {
			t.Fatalf("idempotent call error = %v", err)
		}
	}
	if executor.calls.Load() != 1 || recorder.calls.Load() != 1 {
		t.Fatalf("executions=%d audit records=%d", executor.calls.Load(), recorder.calls.Load())
	}
}

func TestBrokerRejectsChangedIdempotentBodyAndRateOverflow(t *testing.T) {
	executor := &testExecutor{output: []byte(`{"ok":true}`)}
	broker := New(&testLease{}, testPolicy{}, executor, nil, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	d := descriptor()
	d.RateLimit = "1/s"
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Invoke(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	changed := request()
	changed.Parameters = []byte(`{"changed":true}`)
	if _, err := broker.Invoke(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency error = %v", err)
	}
	second := request()
	second.RequestID = "req-2"
	if _, err := broker.Invoke(context.Background(), second); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate error = %v", err)
	}
}

func TestBrokerReauthorizesCachedIdempotentResult(t *testing.T) {
	lease := &testLease{failAt: 2}
	executor := &testExecutor{output: []byte(`{"ok":true}`)}
	broker := New(lease, testPolicy{}, executor, nil, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	if err := broker.Register(descriptor()); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Invoke(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Invoke(context.Background(), request()); !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("cached invocation with revoked lease error = %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("executions = %d", executor.calls)
	}
}

func TestBrokerPropagatesCancellationAndBoundsInput(t *testing.T) {
	executor := &concurrentExecutor{gate: make(chan struct{})}
	broker := New(concurrentLease{}, testPolicy{}, executor, nil, &concurrentRecorder{}, nil, time.Now)
	if err := broker.Register(descriptor()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := broker.Invoke(ctx, request()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	oversized := request()
	oversized.RequestID = "oversized"
	oversized.Parameters = append([]byte(`{"value":"`), make([]byte, maxInputBytes)...)
	oversized.Parameters = append(oversized.Parameters, []byte(`"}`)...)
	if _, err := broker.Invoke(context.Background(), oversized); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized input error = %v", err)
	}
}
