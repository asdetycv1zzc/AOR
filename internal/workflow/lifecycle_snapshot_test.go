package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
	"go.temporal.io/sdk/converter"
)

func TestTemporalProjectLifecycleHistoryQueriesAuthoritativeSnapshot(t *testing.T) {
	client := &lifecycleQueryClient{value: lifecycleEncodedValue{snapshot: ProjectLifecycleSnapshot{
		TenantID: "tenant_1", ProjectID: "project_1", State: contracts.ProjectPlanning,
		ProjectVersion: 4, ProcessedEvents: 3, RejectedSignals: 1,
	}}}
	source, err := NewTemporalProjectLifecycleHistory(client)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.Snapshot(context.Background(), "tenant_1", "project_1")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ProjectVersion != 4 || snapshot.State != contracts.ProjectPlanning || client.workflowID != "aor-project-tenant_1-project_1" || client.queryType != ProjectLifecycleQueryName {
		t.Fatalf("history snapshot = %#v, query = %s/%s", snapshot, client.workflowID, client.queryType)
	}

	client.value = lifecycleEncodedValue{snapshot: ProjectLifecycleSnapshot{
		TenantID: "other", ProjectID: "project_1", State: contracts.ProjectPlanning, ProjectVersion: 4,
	}}
	if _, err := source.Snapshot(context.Background(), "tenant_1", "project_1"); !errors.Is(err, ErrInvalidProjectLifecycle) {
		t.Fatalf("mismatched history identity error = %v", err)
	}
}

type lifecycleQueryClient struct {
	value      converter.EncodedValue
	workflowID string
	queryType  string
}

func (client *lifecycleQueryClient) QueryWorkflow(_ context.Context, workflowID, _ string, queryType string, _ ...interface{}) (converter.EncodedValue, error) {
	client.workflowID = workflowID
	client.queryType = queryType
	return client.value, nil
}

type lifecycleEncodedValue struct {
	snapshot ProjectLifecycleSnapshot
}

func (value lifecycleEncodedValue) HasValue() bool { return true }

func (value lifecycleEncodedValue) Get(destination interface{}) error {
	snapshot, ok := destination.(*ProjectLifecycleSnapshot)
	if !ok {
		return errors.New("unexpected lifecycle query destination")
	}
	*snapshot = value.snapshot
	return nil
}
