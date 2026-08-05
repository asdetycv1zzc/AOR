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
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestEventingScopeResolverLoadsBoundProject(t *testing.T) {
	store := eventing.NewMemoryStore()
	tenantID := "11111111-1111-4111-8111-111111111111"
	projectID := "22222222-2222-4222-8222-222222222222"
	project := state.Project{TenantID: tenantID, ID: projectID, State: contracts.ProjectCreated, Version: 1, DataClassification: "INTERNAL"}
	seedKnowledgeProjection(t, store, tenantID, projectID, "project", projectID, project)
	resolver, err := NewEventingScopeResolver(store)
	if err != nil {
		t.Fatal(err)
	}
	projectScope, err := resolver.ResolveProject(context.Background(), tenantID, projectID)
	if err != nil || projectScope.ID != projectID || projectScope.StateVersion != 1 || projectScope.Classification != "INTERNAL" {
		t.Fatalf("project scope=%#v err=%v", projectScope, err)
	}
}

func TestEventingScopeResolverRejectsMismatchedProjectionEnvelope(t *testing.T) {
	tenantID := "11111111-1111-4111-8111-111111111111"
	projectID := "22222222-2222-4222-8222-222222222222"
	project := state.Project{TenantID: tenantID, ID: projectID, State: contracts.ProjectCreated, Version: 1, DataClassification: "INTERNAL"}
	content, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewEventingScopeResolver(fixedKnowledgeProjectionStore{projection: eventing.Projection{
		TenantID: tenantID, ProjectID: "33333333-3333-4333-8333-333333333333",
		AggregateType: "project", AggregateID: projectID, Version: 1, State: content,
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.ResolveProject(context.Background(), tenantID, projectID)
	assertErrorCode(t, err, aorerrors.CodeArtifactHashMismatch)
}

type fixedKnowledgeProjectionStore struct {
	projection eventing.Projection
}

func (store fixedKnowledgeProjectionStore) Load(context.Context, string, string, string) (eventing.Projection, bool, error) {
	return store.projection, true, nil
}

func (fixedKnowledgeProjectionStore) Lookup(context.Context, string, string, string, string) (eventing.TransactionResult, bool, error) {
	return eventing.TransactionResult{}, false, nil
}

func (fixedKnowledgeProjectionStore) Execute(context.Context, eventing.TransactionRequest) (eventing.TransactionResult, error) {
	return eventing.TransactionResult{}, nil
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
