package toolbroker

import (
	"context"
	"errors"
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

func (l *testLease) Validate(_ context.Context, validation LeaseValidation) error {
	l.validations = append(l.validations, validation)
	if validation.Lease.ID == "" || validation.Lease.FencingToken < 1 || validation.Principal.ID == "" || validation.Principal.Type == "" || validation.Principal.Role == "" || validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" || validation.ToolID == "" || validation.ToolVersion == "" || validation.MCPServerID == "" || validation.Action != "tool.invoke" || validation.Resource == "" || validation.ParameterSHA256 == "" || validation.PolicyVersion == "" || validation.BudgetToken == "" || validation.At.IsZero() {
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

func (e *testExecutor) Execute(context.Context, ToolDescriptor, []byte) ([]byte, error) {
	e.calls++
	return append([]byte(nil), e.output...), nil
}

type testRecorder struct{ calls int }

func (r *testRecorder) Record(context.Context, Invocation) error { r.calls++; return nil }

type testArtifacts struct{ called bool }

func (a *testArtifacts) Put(_ context.Context, data []byte, _ string) (ArtifactRef, error) {
	a.called = true
	return ArtifactRef{URI: "artifact://out", SHA256: "sha256:out", Size: int64(len(data))}, nil
}

func descriptor() ToolDescriptor {
	return ToolDescriptor{ToolID: "repo.read", Version: "1.0.0", MCPServerID: "repo", InputSchemaRef: "urn:in", OutputSchemaRef: "urn:out", InputSchema: []byte(`{"type":"object"}`), OutputSchema: []byte(`{"type":"object"}`), Risk: RiskLow, SideEffect: SideEffectNone, NetworkAccess: NetworkNone, FilesystemAccess: FilesystemRead, RequiresApproval: ApprovalNever, AllowedRoles: []string{"EXECUTOR"}, RateLimit: "10/s", TimeoutSeconds: 10, MaxOutputBytes: 100}
}

func request() ToolRequest {
	return ToolRequest{RequestID: "req", TenantID: "ten", ProjectID: "prj", TaskID: "task", Principal: Principal{ID: "agt", Type: "AGENT_INSTANCE", Role: "EXECUTOR"}, Lease: Lease{ID: "lease", ExpiresAt: brokerTestNow.Add(time.Hour).Format(time.RFC3339), FencingToken: 1}, ToolID: "repo.read", Version: "1.0.0", Parameters: []byte(`{}`), PolicyVersion: "policy-1", BudgetToken: "budget-1"}
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

func TestBrokerSpillsLargeOutputAndDeniesPrivateNetwork(t *testing.T) {
	d := descriptor()
	d.MaxOutputBytes = 10
	d.NetworkAccess = NetworkAllowlist
	artifacts := &testArtifacts{}
	executor := &testExecutor{output: []byte(`{"large":"123456789012345"}`)}
	broker := New(&testLease{}, testPolicy{}, executor, artifacts, &testRecorder{}, nil, func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	result, err := broker.Invoke(context.Background(), request())
	if err != nil || result.Artifact == nil || !artifacts.called {
		t.Fatalf("artifact result = %#v err=%v", result, err)
	}
	requestWithURL := request()
	requestWithURL.Parameters = []byte(`{"url":"http://127.0.0.1/"}`)
	_, err = broker.Invoke(context.Background(), requestWithURL)
	if !errors.Is(err, ErrNetworkDenied) {
		t.Fatalf("network error = %v", err)
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
