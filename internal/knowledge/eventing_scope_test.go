package knowledge

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestEventingScopeResolverLoadsBoundProjectAndTask(t *testing.T) {
	store := eventing.NewMemoryStore()
	tenantID := "11111111-1111-4111-8111-111111111111"
	projectID := "22222222-2222-4222-8222-222222222222"
	taskID := "33333333-3333-4333-8333-333333333333"
	project := state.Project{TenantID: tenantID, ID: projectID, State: contracts.ProjectCreated, Version: 1, DataClassification: "INTERNAL"}
	task := state.ModuleTask{TenantID: tenantID, ProjectID: projectID, ID: taskID, State: contracts.TaskDefined, Version: 1, ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
	seedKnowledgeProjection(t, store, tenantID, projectID, "project", projectID, project)
	seedKnowledgeProjection(t, store, tenantID, projectID, "task", taskID, task)
	resolver, err := NewEventingScopeResolver(store)
	if err != nil {
		t.Fatal(err)
	}
	projectScope, err := resolver.ResolveProject(context.Background(), tenantID, projectID)
	if err != nil || projectScope.ID != projectID || projectScope.StateVersion != 1 || projectScope.Classification != "INTERNAL" {
		t.Fatalf("project scope=%#v err=%v", projectScope, err)
	}
	taskScope, err := resolver.ResolveTask(context.Background(), tenantID, projectID, taskID)
	if err != nil || taskScope.ID != taskID || taskScope.SpecDigest != task.ModuleSpecRef.SHA256 {
		t.Fatalf("task scope=%#v err=%v", taskScope, err)
	}
}

func seedKnowledgeProjection(t *testing.T, store eventing.Store, tenantID, projectID, aggregateType, aggregateID string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Execute(context.Background(), eventing.TransactionRequest{
		TenantID: tenantID, PrincipalID: "seed", IdempotencyKey: aggregateType + "-" + aggregateID,
		RequestSHA256: digest, Result: content, ResultSHA256: digest,
		Updates: []eventing.ProjectionUpdate{{TenantID: tenantID, ProjectID: projectID, AggregateType: aggregateType, AggregateID: aggregateID, ExpectedVersion: 0, NextVersion: 1, State: content}},
		Events:  []eventing.DomainEvent{{EventID: "event-" + aggregateType + "-" + aggregateID, TenantID: tenantID, ProjectID: projectID, AggregateType: aggregateType, AggregateID: aggregateID, AggregateVersion: 1, Type: "io.aor.test.v1", Payload: content, PayloadSHA256: digest, OccurredAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}},
	})
	if err != nil {
		t.Fatal(err)
	}
}
