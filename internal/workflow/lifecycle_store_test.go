package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/contracts"
	"go.temporal.io/api/serviceerror"
	temporalclient "go.temporal.io/sdk/client"
)

func TestProjectLifecycleStoreStartsThenSignalsCommittedProjection(t *testing.T) {
	backing := &lifecycleStoreStub{}
	client := &lifecycleRuntimeClient{}
	store, err := NewProjectLifecycleStore(backing, client, "aor-control-plane")
	if err != nil {
		t.Fatal(err)
	}

	created := lifecycleDomainEvent(t, 1, "io.aor.project.created.v1", contracts.ProjectCreated)
	backing.executeResult = eventing.TransactionResult{Events: []eventing.DomainEvent{created}}
	if _, err := store.Execute(context.Background(), eventing.TransactionRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(client.inputs) != 1 || client.inputs[0].ProjectVersion != 1 || len(client.signals) != 0 {
		t.Fatalf("inputs = %#v signals = %#v", client.inputs, client.signals)
	}

	client.alreadyStarted = true
	negotiating := lifecycleDomainEvent(t, 2, "io.aor.goal.negotiation-started.v1", contracts.ProjectGoalNegotiating)
	backing.executeResult = eventing.TransactionResult{Events: []eventing.DomainEvent{negotiating}}
	if _, err := store.Execute(context.Background(), eventing.TransactionRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(client.signals) != 1 || client.signals[0].AggregateVersion != 2 || client.signals[0].State != contracts.ProjectGoalNegotiating {
		t.Fatalf("signals = %#v", client.signals)
	}
}

func TestProjectLifecycleStoreRetriesSynchronizationOnIdempotentLookup(t *testing.T) {
	event := lifecycleDomainEvent(t, 3, "io.aor.goal.approved.v1", contracts.ProjectPlanning)
	backing := &lifecycleStoreStub{lookupFound: true, lookupResult: eventing.TransactionResult{Events: []eventing.DomainEvent{event}, Duplicate: true}}
	client := &lifecycleRuntimeClient{alreadyStarted: true, signalErr: errors.New("temporal unavailable")}
	store, err := NewProjectLifecycleStore(backing, client, "aor-control-plane")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Lookup(context.Background(), "tenant-1", "user-1", "key-1", "sha256:test"); found || !errors.Is(err, ErrProjectLifecycleSynchronization) {
		t.Fatalf("first lookup found = %v error = %v", found, err)
	}
	client.signalErr = nil
	result, found, err := store.Lookup(context.Background(), "tenant-1", "user-1", "key-1", "sha256:test")
	if err != nil || !found || !result.Duplicate || len(client.signals) != 1 {
		t.Fatalf("result = %#v found = %v error = %v signals = %#v", result, found, err, client.signals)
	}
}

func TestProjectLifecycleStoreAdoptsExistingProjectAtCheckpoint(t *testing.T) {
	backing := &lifecycleStoreStub{executeResult: eventing.TransactionResult{Events: []eventing.DomainEvent{
		lifecycleDomainEvent(t, 7, "io.aor.approval.committed.v1", contracts.ProjectGlobalAudit),
	}}}
	client := &lifecycleRuntimeClient{}
	store, err := NewProjectLifecycleStore(backing, client, "aor-control-plane")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(context.Background(), eventing.TransactionRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(client.inputs) != 1 || client.inputs[0].ProjectVersion != 7 || client.inputs[0].State != contracts.ProjectGlobalAudit || client.inputs[0].ProcessedEvents != 6 || len(client.signals) != 0 {
		t.Fatalf("inputs = %#v signals = %#v", client.inputs, client.signals)
	}
}

type lifecycleStoreStub struct {
	executeResult eventing.TransactionResult
	executeErr    error
	lookupResult  eventing.TransactionResult
	lookupFound   bool
	lookupErr     error
}

func (store *lifecycleStoreStub) Load(context.Context, string, string, string) (eventing.Projection, bool, error) {
	return eventing.Projection{}, false, nil
}

func (store *lifecycleStoreStub) Lookup(context.Context, string, string, string, string) (eventing.TransactionResult, bool, error) {
	return store.lookupResult, store.lookupFound, store.lookupErr
}

func (store *lifecycleStoreStub) Execute(context.Context, eventing.TransactionRequest) (eventing.TransactionResult, error) {
	return store.executeResult, store.executeErr
}

type lifecycleRuntimeClient struct {
	alreadyStarted bool
	signalErr      error
	inputs         []ProjectLifecycleInput
	signals        []ProjectLifecycleEvent
}

func (client *lifecycleRuntimeClient) ExecuteWorkflow(_ context.Context, _ temporalclient.StartWorkflowOptions, _ interface{}, args ...interface{}) (temporalclient.WorkflowRun, error) {
	input, ok := args[0].(ProjectLifecycleInput)
	if !ok {
		return nil, errors.New("invalid lifecycle input")
	}
	client.inputs = append(client.inputs, input)
	if client.alreadyStarted {
		return nil, serviceerror.NewWorkflowExecutionAlreadyStarted("exists", "request", "run-1")
	}
	return nil, nil
}

func (client *lifecycleRuntimeClient) SignalWorkflow(_ context.Context, _, _, _ string, value interface{}) error {
	if client.signalErr != nil {
		return client.signalErr
	}
	signal, ok := value.(ProjectLifecycleEvent)
	if !ok {
		return errors.New("invalid lifecycle signal")
	}
	client.signals = append(client.signals, signal)
	return nil
}

func lifecycleDomainEvent(t *testing.T, version int64, eventType string, projectState contracts.ProjectState) eventing.DomainEvent {
	t.Helper()
	projection := lifecycleProjectProjection{
		TenantID: "tenant-1", ID: "project-1", CreatedBy: "user-1", GoalAgentCount: 2,
		State: projectState, Version: version,
	}
	payload, err := json.Marshal(struct {
		TenantID         string                     `json:"tenantId"`
		ProjectID        string                     `json:"projectId"`
		AggregateVersion int64                      `json:"aggregateVersion"`
		Projection       lifecycleProjectProjection `json:"projection"`
	}{TenantID: "tenant-1", ProjectID: "project-1", AggregateVersion: version, Projection: projection})
	if err != nil {
		t.Fatal(err)
	}
	return eventing.DomainEvent{
		EventID: "event-" + time.Unix(version, 0).UTC().Format("150405"), TenantID: "tenant-1", ProjectID: "project-1",
		AggregateType: "project", AggregateID: "project-1", AggregateVersion: version, Type: eventType,
		Payload: payload, PayloadSHA256: "sha256:" + repeatHex(byte(version)), OccurredAt: time.Unix(version, 0).UTC(),
	}
}

var _ eventing.Store = (*lifecycleStoreStub)(nil)
var _ projectLifecycleSignalClient = (*lifecycleRuntimeClient)(nil)
