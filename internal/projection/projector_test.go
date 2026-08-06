package projection

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestProjectorBuffersOutOfOrderAndDeduplicates(t *testing.T) {
	projector := New(map[string]Reducer{"project": replaceReducer})
	events := []eventing.DomainEvent{projectionEvent(1), projectionEvent(2), projectionEvent(3)}
	order := []eventing.DomainEvent{events[2], events[0], events[0], events[1]}
	var applied []eventing.DomainEvent
	for _, event := range order {
		batch, err := projector.Apply(event)
		if err != nil {
			t.Fatal(err)
		}
		applied = append(applied, batch...)
	}
	if len(applied) != 3 || applied[0].AggregateVersion != 1 || applied[2].AggregateVersion != 3 {
		t.Fatalf("applied = %#v", applied)
	}
	snapshot, found := projector.Snapshot("tenant_1", "project", "prj_1")
	if !found || snapshot.Version != 3 || string(snapshot.State) != `{"state":"v3"}` {
		t.Fatalf("snapshot = %#v, %v", snapshot, found)
	}
}

func TestProjectorScopesStreamsByTenant(t *testing.T) {
	projector := New(map[string]Reducer{"project": replaceReducer})
	first := projectionEvent(1)
	second := projectionEvent(1)
	second.EventID = "evt_tenant_2"
	second.TenantID = "tenant_2"
	second.Payload = json.RawMessage(`{"state":"tenant-2"}`)
	second.PayloadSHA256, _ = canonicaljson.Digest(second.Payload)
	if _, err := projector.Apply(first); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Apply(second); err != nil {
		t.Fatal(err)
	}
	firstSnapshot, firstFound := projector.Snapshot("tenant_1", "project", "prj_1")
	secondSnapshot, secondFound := projector.Snapshot("tenant_2", "project", "prj_1")
	if !firstFound || !secondFound || string(firstSnapshot.State) != `{"state":"v1"}` || string(secondSnapshot.State) != `{"state":"tenant-2"}` {
		t.Fatalf("tenant snapshots = %#v, %#v", firstSnapshot, secondSnapshot)
	}
}

func TestProjectorRetriesEventAfterReducerFailure(t *testing.T) {
	fail := true
	projector := New(map[string]Reducer{"project": func(_ json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error) {
		if fail {
			fail = false
			return nil, errors.New("temporary reducer failure")
		}
		return append(json.RawMessage(nil), event.Payload...), nil
	}})
	event := projectionEvent(1)
	if _, err := projector.Apply(event); err == nil {
		t.Fatal("first reducer call unexpectedly succeeded")
	}
	if _, err := projector.Apply(event); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	snapshot, found := projector.Snapshot("tenant_1", "project", "prj_1")
	if !found || snapshot.Version != 1 {
		t.Fatalf("retry snapshot = %#v, %v", snapshot, found)
	}
}

func TestProjectorAcceptsGapCloserAtPendingLimit(t *testing.T) {
	projector := New(map[string]Reducer{"project": replaceReducer})
	for version := int64(2); version <= maxPendingPerAggregate+1; version++ {
		event := projectionEventVersion(version)
		if _, err := projector.Apply(event); err != nil {
			t.Fatalf("buffer version %d: %v", version, err)
		}
	}
	if _, err := projector.Apply(projectionEventVersion(1)); err != nil {
		t.Fatalf("gap closer rejected: %v", err)
	}
	snapshot, found := projector.Snapshot("tenant_1", "project", "prj_1")
	if !found || snapshot.Version != maxPendingPerAggregate+1 {
		t.Fatalf("drained snapshot = %#v, %v", snapshot, found)
	}
}

func TestProjectorRejectsConflictingVersion(t *testing.T) {
	projector := New(map[string]Reducer{"project": replaceReducer})
	if _, err := projector.Apply(projectionEvent(1)); err != nil {
		t.Fatal(err)
	}
	conflict := projectionEvent(1)
	conflict.EventID = "evt_conflict"
	conflict.Payload = json.RawMessage(`{"state":"other"}`)
	conflict.PayloadSHA256, _ = canonicaljson.Digest(conflict.Payload)
	_, err := projector.Apply(conflict)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeConflict {
		t.Fatalf("conflict = %#v", err)
	}
}

func TestProjectorAcceptsBudgetSnapshotVersionGaps(t *testing.T) {
	projector := New(nil)
	second := budgetProjectionEvent(5, 4, 200)
	first := budgetProjectionEvent(2, 1, 150)
	if _, err := projector.Apply(second); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Apply(first); err != nil {
		t.Fatal(err)
	}
	snapshot, found := projector.Snapshot("tenant_1", "budget", "account-1")
	if !found || snapshot.Version != 5 || string(snapshot.State) != string(second.ReplayState) {
		t.Fatalf("budget snapshot = %#v, %v", snapshot, found)
	}
	conflict := budgetProjectionEvent(5, 4, 250)
	_, err := projector.Apply(conflict)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeConflict {
		t.Fatalf("budget version conflict = %v", err)
	}
}

func replaceReducer(_ json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error) {
	return append(json.RawMessage(nil), event.Payload...), nil
}

func projectionEvent(version int64) eventing.DomainEvent {
	payload := json.RawMessage(`{"state":"v1"}`)
	if version == 2 {
		payload = json.RawMessage(`{"state":"v2"}`)
	}
	if version == 3 {
		payload = json.RawMessage(`{"state":"v3"}`)
	}
	digest, _ := canonicaljson.Digest(payload)
	return eventing.DomainEvent{
		EventID: "evt_" + string(rune('0'+version)), TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", AggregateVersion: version,
		Type: "io.aor.project.changed.v1", Payload: payload, PayloadSHA256: digest, OccurredAt: time.Date(2030, 1, 1, 0, 0, int(version), 0, time.UTC),
	}
}

func projectionEventVersion(version int64) eventing.DomainEvent {
	payload := json.RawMessage(`{"state":"buffered"}`)
	digest, _ := canonicaljson.Digest(payload)
	return eventing.DomainEvent{
		EventID: "evt_buffer_" + time.Unix(version, 0).UTC().Format(time.RFC3339), TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", AggregateVersion: version,
		Type: "io.aor.project.changed.v1", Payload: payload, PayloadSHA256: digest, OccurredAt: time.Unix(version, 0).UTC(),
	}
}

func budgetProjectionEvent(version, previous, hardLimit int64) eventing.DomainEvent {
	payload := json.RawMessage(fmt.Sprintf(`{"tenantId":"tenant_1","projectId":"prj_1","accountId":"account-1","principalId":"admin","previousVersion":%d,"aggregateVersion":%d,"version":%d,"hardLimitMinor":%d,"softLimitMinor":%d,"currency":"USD","reason":"approved"}`, previous, version, version, hardLimit, hardLimit-1))
	digest, _ := canonicaljson.Digest(payload)
	return eventing.DomainEvent{EventID: fmt.Sprintf("budget-%d-%d", version, hardLimit), TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "budget", AggregateID: "account-1", AggregateVersion: version, Type: "io.aor.budget.adjusted.v1", Payload: payload, PayloadSHA256: digest, ReplayState: append(json.RawMessage(nil), payload...), ReplayStateSHA256: digest, OccurredAt: time.Unix(version, 0).UTC()}
}
