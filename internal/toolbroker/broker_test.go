package toolbroker

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testLease struct{}

func (testLease) Validate(context.Context, Lease, Principal, string, string, string) error {
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
	return ToolRequest{RequestID: "req", TenantID: "ten", ProjectID: "prj", TaskID: "task", Principal: Principal{ID: "agt", Type: "AGENT_INSTANCE", Role: "EXECUTOR"}, Lease: Lease{ID: "lease"}, ToolID: "repo.read", Version: "1.0.0", Parameters: []byte(`{}`)}
}

func TestBrokerStableListAndInvocation(t *testing.T) {
	executor := &testExecutor{output: []byte(`{"ok":true}`)}
	recorder := &testRecorder{}
	broker := New(testLease{}, testPolicy{}, executor, nil, recorder, nil, func() time.Time { return time.Unix(0, 0) })
	if err := broker.Register(descriptor()); err != nil {
		t.Fatal(err)
	}
	result, err := broker.Invoke(context.Background(), request())
	if err != nil || string(result.Output) != `{"ok":true}` || recorder.calls != 1 || executor.calls != 1 {
		t.Fatalf("result = %#v err=%v", result, err)
	}
}

func TestBrokerRejectsIrreversibleCallWithoutRevalidation(t *testing.T) {
	d := descriptor()
	d.SideEffect = SideEffectIrreversible
	broker := New(testLease{}, testPolicy{}, &testExecutor{output: []byte(`{}`)}, nil, &testRecorder{}, nil, time.Now)
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
	broker := New(testLease{}, testPolicy{}, executor, artifacts, &testRecorder{}, nil, time.Now)
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
