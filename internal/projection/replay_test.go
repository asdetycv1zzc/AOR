package projection

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func TestRebuildConvergesAfterCommitPublishAndDeliveryFaults(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store := eventing.NewMemoryStore()

	first := rebuildTransaction(t, 1, now)
	store.FailNext(eventing.FailureBeforeCommit)
	if _, err := store.Execute(ctx, first); !errors.Is(err, eventing.ErrInjectedFailure) {
		t.Fatalf("before-commit fault = %v", err)
	}
	if stats := store.Stats(); stats.Events != 0 || stats.Projections != 0 {
		t.Fatalf("before-commit state = %#v", stats)
	}
	if result, err := store.Execute(ctx, first); err != nil || result.Duplicate {
		t.Fatalf("first commit = %#v, %v", result, err)
	}

	second := rebuildTransaction(t, 2, now)
	store.FailNext(eventing.FailureAfterCommit)
	if _, err := store.Execute(ctx, second); !errors.Is(err, eventing.ErrCommitResultUnknown) {
		t.Fatalf("after-commit fault = %v", err)
	}
	if result, err := store.Execute(ctx, second); err != nil || !result.Duplicate {
		t.Fatalf("after-commit retry = %#v, %v", result, err)
	}

	online := New(map[string]Reducer{"project": StateReducer})
	bus := &replayDeliveryBus{projector: online, failFirst: map[string]bool{first.Events[0].EventID: true}}
	publisher, err := eventing.NewOutboxPublisher(store, bus, eventing.OutboxPublisherConfig{
		BatchSize: 2, Concurrency: 1, ClaimTTL: 10 * time.Second, PublishTimeout: 5 * time.Second,
		InitialBackoff: time.Second, MaxBackoff: time.Second, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := publisher.RunOnce(ctx, "tenant_1"); err != nil || result.Claimed != 2 || result.Published != 1 || result.Retried != 1 {
		t.Fatalf("initial publish = %#v, %v", result, err)
	}
	now = now.Add(time.Second)
	if result, err := publisher.RunOnce(ctx, "tenant_1"); err != nil || result.Claimed != 1 || result.Published != 1 || result.Retried != 0 {
		t.Fatalf("recovered publish = %#v, %v", result, err)
	}

	rebuilt, err := Rebuild(ctx, store, "tenant_1", map[string]Reducer{"project": StateReducer})
	if err != nil {
		t.Fatal(err)
	}
	onlineSnapshot, found := online.Snapshot("tenant_1", "project", "prj_1")
	if !found {
		t.Fatal("online event-bus projection is missing")
	}
	rebuiltSnapshot, found := rebuilt.Snapshot("tenant_1", "project", "prj_1")
	if !found {
		t.Fatal("rebuilt projection is missing")
	}
	onlineDigest, err := onlineSnapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rebuiltDigest, err := rebuiltSnapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if rebuiltDigest != onlineDigest {
		t.Fatalf("event-bus digest = %s, rebuilt digest = %s", onlineDigest, rebuiltDigest)
	}

	persisted, found, err := store.Load(ctx, "tenant_1", "project", "prj_1")
	if err != nil || !found {
		t.Fatalf("online projection = %#v, %v, %v", persisted, found, err)
	}
	persistedDigest, err := (Snapshot{Version: persisted.Version, State: persisted.State}).Digest()
	if err != nil {
		t.Fatal(err)
	}
	if rebuiltDigest != persistedDigest {
		t.Fatalf("persisted digest = %s, rebuilt digest = %s", persistedDigest, rebuiltDigest)
	}
}

func TestReconcileReportsDurableProjectionDriftDeterministically(t *testing.T) {
	ctx := context.Background()
	store := eventing.NewMemoryStore()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := store.Execute(ctx, rebuildTransaction(t, 1, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(ctx, rebuildTransaction(t, 2, now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	reducers := map[string]Reducer{"project": StateReducer}
	report, err := Reconcile(ctx, store, store, "tenant_1", reducers)
	if err != nil || !report.Converged || len(report.Drifts) != 0 || report.ReportSHA256 == "" || report.RebuiltSHA256 != report.OnlineSHA256 {
		t.Fatalf("converged report=%#v err=%v", report, err)
	}

	projections, err := store.ListTenantProjections(ctx, "tenant_1")
	if err != nil || len(projections) != 1 {
		t.Fatalf("projections=%#v err=%v", projections, err)
	}
	drifted := append([]eventing.Projection(nil), projections...)
	drifted[0].State = json.RawMessage(`{"id":"prj_1","version":2,"state":"DRIFTED"}`)
	drifted = append(drifted, eventing.Projection{TenantID: "tenant_1", ProjectID: "prj_orphan", AggregateType: "project", AggregateID: "prj_orphan", Version: 1, State: json.RawMessage(`{"id":"prj_orphan","version":1}`)})
	report, err = Reconcile(ctx, store, staticProjectionCatalog{projections: drifted}, "tenant_1", reducers)
	if err != nil || report.Converged || len(report.Drifts) != 2 || report.Drifts[0].Kind != DriftState || report.Drifts[1].Kind != DriftOrphanOnline {
		t.Fatalf("drift report=%#v err=%v", report, err)
	}
	again, err := Reconcile(ctx, store, staticProjectionCatalog{projections: drifted}, "tenant_1", reducers)
	if err != nil || again.ReportSHA256 != report.ReportSHA256 {
		t.Fatalf("report digest first=%q second=%q err=%v", report.ReportSHA256, again.ReportSHA256, err)
	}

	missing, err := Reconcile(ctx, store, staticProjectionCatalog{}, "tenant_1", reducers)
	if err != nil || len(missing.Drifts) != 1 || missing.Drifts[0].Kind != DriftMissingOnline {
		t.Fatalf("missing report=%#v err=%v", missing, err)
	}
}

type staticProjectionCatalog struct {
	projections []eventing.Projection
}

func (catalog staticProjectionCatalog) ListTenantProjections(ctx context.Context, tenantID string) ([]eventing.Projection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]eventing.Projection, 0, len(catalog.projections))
	for _, projection := range catalog.projections {
		if projection.TenantID == tenantID {
			projection.State = append(json.RawMessage(nil), projection.State...)
			result = append(result, projection)
		}
	}
	return result, nil
}

type replayDeliveryBus struct {
	projector *Projector
	failFirst map[string]bool
}

func (b *replayDeliveryBus) Publish(ctx context.Context, event eventing.DomainEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.failFirst[event.EventID] {
		delete(b.failFirst, event.EventID)
		return errors.New("injected publish failure")
	}
	if _, err := b.projector.Apply(event); err != nil {
		return err
	}
	_, err := b.projector.Apply(event)
	return err
}

func rebuildTransaction(t *testing.T, version int64, occurredAt time.Time) eventing.TransactionRequest {
	t.Helper()
	state, err := json.Marshal(struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
		State   string `json:"state"`
	}{ID: "prj_1", Version: version, State: "VERSION_" + string(rune('0'+version))})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		TenantID         string          `json:"tenantId"`
		ProjectID        string          `json:"projectId"`
		AggregateVersion int64           `json:"aggregateVersion"`
		Projection       json.RawMessage `json:"projection"`
	}{TenantID: "tenant_1", ProjectID: "prj_1", AggregateVersion: version, Projection: state})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := canonicaljson.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := canonicaljson.Digest(state)
	if err != nil {
		t.Fatal(err)
	}
	return eventing.TransactionRequest{
		TenantID: "tenant_1", PrincipalID: "svc_workflow", IdempotencyKey: "transition_" + string(rune('0'+version)), RequestSHA256: requestDigest,
		Updates: []eventing.ProjectionUpdate{{TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", ExpectedVersion: version - 1, NextVersion: version, State: state}},
		Events:  []eventing.DomainEvent{{EventID: "evt_" + string(rune('0'+version)), TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", AggregateVersion: version, Type: "io.aor.project.changed.v1", Payload: payload, PayloadSHA256: payloadDigest, OccurredAt: occurredAt}},
		Result:  state, ResultSHA256: requestDigest,
	}
}
