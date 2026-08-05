package knowledge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
)

type tamperedKnowledgeEventStore struct {
	*eventing.MemoryStore
}

func (store *tamperedKnowledgeEventStore) ListEvents(ctx context.Context, tenantID string) ([]eventing.DomainEvent, error) {
	events, err := store.MemoryStore.ListEvents(ctx, tenantID)
	if err == nil && len(events) > 0 {
		events[0].Payload = []byte(`{"tampered":true}`)
	}
	return events, err
}

func TestKnowledgeUpdatePublishesOneSignedEvent(t *testing.T) {
	store := eventing.NewMemoryStore()
	signer, err := NewHMACKnowledgeUpdatedSigner([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	publisher, err := NewEventKnowledgeUpdatedPublisher(store, signer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	previous := "sha256:" + strings.Repeat("1", 64)
	revision := "sha256:" + strings.Repeat("2", 64)
	digest := "sha256:" + strings.Repeat("3", 64)
	access := Access{
		Principal: authn.Principal{ID: "curator-1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator},
		TenantID:  "tenant-1", ProjectID: "project-1",
		Approval: &authz.Approval{ID: "approval-1"}, Lease: &authz.LeaseReference{ID: "lease-1"},
	}
	result := UpdateResult{Manifest: Manifest{TenantID: access.TenantID, ProjectID: access.ProjectID, Revision: revision}, Digest: digest}
	index := IndexSnapshot{TenantID: access.TenantID, ProjectID: access.ProjectID, Revision: revision, BuiltAt: now, Documents: 4}
	for range 2 {
		if err := publisher.Publish(context.Background(), access, previous, result, index); err != nil {
			t.Fatal(err)
		}
	}
	if stats := store.Stats(); stats.Events != 1 || stats.Projections != 1 {
		t.Fatalf("store stats = %#v", stats)
	}
	projection, found, err := store.Load(context.Background(), access.TenantID, knowledgeAggregateType, access.ProjectID)
	if err != nil || !found {
		t.Fatalf("projection found=%v err=%v", found, err)
	}
	var signed KnowledgeUpdatedEvent
	if err := json.Unmarshal(projection.State, &signed); err != nil {
		t.Fatal(err)
	}
	unsigned, err := canonicalKnowledgeUpdatedEvent(signed)
	if err != nil || !signer.Verify(context.Background(), unsigned, signed.Signature) {
		t.Fatalf("signed event verification failed: %v", err)
	}
	events, err := store.ListEvents(context.Background(), access.TenantID)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	external, err := eventing.Externalize(events[0], eventing.CloudEventOptions{Source: "urn:aor:test"})
	if err != nil || external.Type != knowledgeUpdatedEventType || external.TaskID != "" || external.TaskIDReason != "NOT_APPLICABLE" {
		t.Fatalf("external event=%#v err=%v", external, err)
	}
	foundEvent, found, err := publisher.Find(context.Background(), access.TenantID, access.ProjectID, digest, "approval-1")
	if err != nil || !found || foundEvent.ProposalDigest != digest || foundEvent.ApprovalID != "approval-1" {
		t.Fatalf("verified lookup found=%v event=%#v err=%v", found, foundEvent, err)
	}
}

func TestKnowledgeUpdatedLookupRejectsTamperedPayload(t *testing.T) {
	store := eventing.NewMemoryStore()
	signer, err := NewHMACKnowledgeUpdatedSigner([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	publisher, err := NewEventKnowledgeUpdatedPublisher(store, signer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	access := Access{
		Principal: authn.Principal{ID: "curator-1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator},
		TenantID:  "tenant-1", ProjectID: "project-1",
		Approval: &authz.Approval{ID: "approval-1"}, Lease: &authz.LeaseReference{ID: "lease-1"},
	}
	digest := "sha256:" + strings.Repeat("3", 64)
	if err := publisher.Publish(context.Background(), access, "sha256:"+strings.Repeat("1", 64), UpdateResult{Manifest: Manifest{TenantID: access.TenantID, ProjectID: access.ProjectID, Revision: "sha256:" + strings.Repeat("2", 64)}, Digest: digest}, IndexSnapshot{TenantID: access.TenantID, ProjectID: access.ProjectID, Revision: "sha256:" + strings.Repeat("2", 64), BuiltAt: now}); err != nil {
		t.Fatal(err)
	}
	tampered := &tamperedKnowledgeEventStore{MemoryStore: store}
	lookup, err := NewEventKnowledgeUpdatedPublisher(tampered, signer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := lookup.Find(context.Background(), access.TenantID, access.ProjectID, digest, "approval-1"); err == nil || found {
		t.Fatalf("tampered lookup found=%v err=%v", found, err)
	}
}
