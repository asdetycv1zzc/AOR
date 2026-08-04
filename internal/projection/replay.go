package projection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var ErrProjectionDrift = errors.New("durable projection reconciliation detected drift")

type DriftKind string

const (
	DriftMissingOnline DriftKind = "MISSING_ONLINE"
	DriftOrphanOnline  DriftKind = "ORPHAN_ONLINE"
	DriftVersion       DriftKind = "VERSION_MISMATCH"
	DriftState         DriftKind = "STATE_MISMATCH"
)

type ProjectionDrift struct {
	Kind           DriftKind `json:"kind"`
	ProjectID      string    `json:"projectId"`
	AggregateType  string    `json:"aggregateType"`
	AggregateID    string    `json:"aggregateId"`
	RebuiltVersion int64     `json:"rebuiltVersion,omitempty"`
	OnlineVersion  int64     `json:"onlineVersion,omitempty"`
	RebuiltSHA256  string    `json:"rebuiltSha256,omitempty"`
	OnlineSHA256   string    `json:"onlineSha256,omitempty"`
}

type ReconciliationReport struct {
	TenantID      string            `json:"tenantId"`
	EventCount    int               `json:"eventCount"`
	RebuiltCount  int               `json:"rebuiltCount"`
	OnlineCount   int               `json:"onlineCount"`
	RebuiltSHA256 string            `json:"rebuiltSha256"`
	OnlineSHA256  string            `json:"onlineSha256"`
	Converged     bool              `json:"converged"`
	Drifts        []ProjectionDrift `json:"drifts"`
	ReportSHA256  string            `json:"reportSha256"`
}

type projectionInventoryItem struct {
	ProjectID     string `json:"projectId"`
	AggregateType string `json:"aggregateType"`
	AggregateID   string `json:"aggregateId"`
	Version       int64  `json:"version"`
	SHA256        string `json:"sha256"`
}

// Rebuild creates a new projector from the complete immutable event log for a
// tenant. The event log is sorted again so every implementation has identical
// replay behavior.
func Rebuild(ctx context.Context, log eventing.EventLog, tenantID string, reducers map[string]Reducer) (*Projector, error) {
	if ctx == nil || log == nil || tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "projection rebuild"})
	}
	events, err := log.ListEvents(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list projection events: %w", err)
	}
	return rebuildEvents(events, tenantID, reducers)
}

func rebuildEvents(source []eventing.DomainEvent, tenantID string, reducers map[string]Reducer) (*Projector, error) {
	events := make([]eventing.DomainEvent, len(source))
	for index, event := range source {
		events[index] = cloneEvent(event)
	}
	sort.Slice(events, func(left, right int) bool {
		if events[left].AggregateType != events[right].AggregateType {
			return events[left].AggregateType < events[right].AggregateType
		}
		if events[left].AggregateID != events[right].AggregateID {
			return events[left].AggregateID < events[right].AggregateID
		}
		if events[left].AggregateVersion != events[right].AggregateVersion {
			return events[left].AggregateVersion < events[right].AggregateVersion
		}
		return events[left].EventID < events[right].EventID
	})
	projector := New(reducers)
	for _, event := range events {
		if event.TenantID != tenantID {
			return nil, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "projection rebuild tenant"})
		}
		if _, err := projector.Apply(event); err != nil {
			return nil, fmt.Errorf("replay event %s: %w", event.EventID, err)
		}
	}
	if err := projector.ensureComplete(); err != nil {
		return nil, err
	}
	return projector, nil
}

// Reconcile rebuilds every tenant aggregate from the immutable event log and
// compares the result with the complete durable projection inventory. Drift is
// returned as data so operators can retain evidence before deciding whether to
// run a forward repair.
func Reconcile(ctx context.Context, log eventing.EventLog, catalog eventing.ProjectionCatalog, tenantID string, reducers map[string]Reducer) (ReconciliationReport, error) {
	if ctx == nil || log == nil || catalog == nil || tenantID == "" {
		return ReconciliationReport{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "projection reconciliation"})
	}
	events, err := log.ListEvents(ctx, tenantID)
	if err != nil {
		return ReconciliationReport{}, fmt.Errorf("list reconciliation events: %w", err)
	}
	online, err := catalog.ListTenantProjections(ctx, tenantID)
	if err != nil {
		return ReconciliationReport{}, fmt.Errorf("list online projections: %w", err)
	}
	return reconcileLoaded(events, online, tenantID, reducers)
}

// ReconcileDurable obtains the immutable event history and complete online
// projection catalogue from one repeatable-read storage snapshot. Replay uses
// only state bound to the immutable event at commit time.
func ReconcileDurable(ctx context.Context, source eventing.ReconciliationSource, tenantID string) (ReconciliationReport, error) {
	if ctx == nil || source == nil || tenantID == "" {
		return ReconciliationReport{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "durable projection reconciliation"})
	}
	snapshot, err := source.LoadReconciliationSnapshot(ctx, tenantID)
	if err != nil {
		return ReconciliationReport{}, fmt.Errorf("load durable reconciliation snapshot: %w", err)
	}
	reducers := make(map[string]Reducer)
	for _, event := range snapshot.Events {
		if event.AggregateType == "" {
			return ReconciliationReport{}, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "reconciliation aggregate type"})
		}
		reducers[event.AggregateType] = AuthoritativeStateReducer
	}
	return reconcileLoaded(snapshot.Events, snapshot.Projections, tenantID, reducers)
}

// VerifyDurable is a fail-closed operator gate. Repair is intentionally not a
// projection-table mutation: relational read models must be corrected through
// a new authoritative domain command and reconciled again.
func VerifyDurable(ctx context.Context, source eventing.ReconciliationSource, tenantID string) (ReconciliationReport, error) {
	report, err := ReconcileDurable(ctx, source, tenantID)
	if err != nil {
		if errors.Is(err, eventing.ErrRelationalProjectionDrift) {
			return ReconciliationReport{}, fmt.Errorf("%w: %v", ErrProjectionDrift, err)
		}
		return ReconciliationReport{}, err
	}
	if !report.Converged {
		return report, fmt.Errorf("%w: report %s contains %d drift records", ErrProjectionDrift, report.ReportSHA256, len(report.Drifts))
	}
	return report, nil
}

func reconcileLoaded(events []eventing.DomainEvent, online []eventing.Projection, tenantID string, reducers map[string]Reducer) (ReconciliationReport, error) {
	rebuilt, err := rebuildEvents(events, tenantID, reducers)
	if err != nil {
		return ReconciliationReport{}, err
	}
	rebuiltItems, rebuiltSnapshots, err := rebuiltInventory(events, rebuilt, tenantID)
	if err != nil {
		return ReconciliationReport{}, err
	}
	onlineItems, onlineSnapshots, err := onlineInventory(online, tenantID)
	if err != nil {
		return ReconciliationReport{}, err
	}
	report := ReconciliationReport{
		TenantID: tenantID, EventCount: len(events), RebuiltCount: len(rebuiltItems), OnlineCount: len(onlineItems),
		Drifts: make([]ProjectionDrift, 0),
	}
	report.RebuiltSHA256, err = inventoryDigest(rebuiltItems)
	if err != nil {
		return ReconciliationReport{}, err
	}
	report.OnlineSHA256, err = inventoryDigest(onlineItems)
	if err != nil {
		return ReconciliationReport{}, err
	}
	keys := make([]string, 0, len(rebuiltSnapshots)+len(onlineSnapshots))
	seen := make(map[string]bool, len(rebuiltSnapshots)+len(onlineSnapshots))
	for key := range rebuiltSnapshots {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range onlineSnapshots {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		expected, expectedFound := rebuiltSnapshots[key]
		actual, actualFound := onlineSnapshots[key]
		drift := ProjectionDrift{ProjectID: expected.ProjectID, AggregateType: expected.AggregateType, AggregateID: expected.AggregateID, RebuiltVersion: expected.Version, RebuiltSHA256: expected.SHA256}
		if !expectedFound {
			drift.ProjectID, drift.AggregateType, drift.AggregateID = actual.ProjectID, actual.AggregateType, actual.AggregateID
			drift.OnlineVersion, drift.OnlineSHA256, drift.Kind = actual.Version, actual.SHA256, DriftOrphanOnline
			report.Drifts = append(report.Drifts, drift)
			continue
		}
		if !actualFound {
			drift.Kind = DriftMissingOnline
			report.Drifts = append(report.Drifts, drift)
			continue
		}
		drift.OnlineVersion, drift.OnlineSHA256 = actual.Version, actual.SHA256
		if expected.Version != actual.Version {
			drift.Kind = DriftVersion
			report.Drifts = append(report.Drifts, drift)
			continue
		}
		if expected.SHA256 != actual.SHA256 {
			drift.Kind = DriftState
			report.Drifts = append(report.Drifts, drift)
		}
	}
	report.Converged = len(report.Drifts) == 0 && report.RebuiltSHA256 == report.OnlineSHA256
	report.ReportSHA256, err = reconciliationDigest(report)
	if err != nil {
		return ReconciliationReport{}, err
	}
	return report, nil
}

func rebuiltInventory(events []eventing.DomainEvent, projector *Projector, tenantID string) ([]projectionInventoryItem, map[string]projectionInventoryItem, error) {
	refs := make(map[string]eventing.DomainEvent)
	for _, event := range events {
		key := aggregateKey(tenantID, event.AggregateType, event.AggregateID)
		if prior, found := refs[key]; !found || event.AggregateVersion > prior.AggregateVersion {
			refs[key] = event
		}
	}
	items := make([]projectionInventoryItem, 0, len(refs))
	byKey := make(map[string]projectionInventoryItem, len(refs))
	for key, ref := range refs {
		snapshot, found := projector.Snapshot(tenantID, ref.AggregateType, ref.AggregateID)
		if !found {
			return nil, nil, aorerrors.New(aorerrors.CodeConflict, ref.CorrelationID, map[string]any{"scope": "rebuilt projection missing"})
		}
		digest, err := snapshot.Digest()
		if err != nil {
			return nil, nil, err
		}
		item := projectionInventoryItem{ProjectID: ref.ProjectID, AggregateType: ref.AggregateType, AggregateID: ref.AggregateID, Version: snapshot.Version, SHA256: digest}
		items = append(items, item)
		byKey[key] = item
	}
	sortInventory(items)
	return items, byKey, nil
}

func onlineInventory(projections []eventing.Projection, tenantID string) ([]projectionInventoryItem, map[string]projectionInventoryItem, error) {
	items := make([]projectionInventoryItem, 0, len(projections))
	byKey := make(map[string]projectionInventoryItem, len(projections))
	for _, projection := range projections {
		if projection.TenantID != tenantID || projection.ProjectID == "" || projection.AggregateType == "" || projection.AggregateID == "" {
			return nil, nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "online projection identity"})
		}
		digest, err := (Snapshot{Version: projection.Version, State: projection.State}).Digest()
		if err != nil {
			return nil, nil, err
		}
		key := aggregateKey(tenantID, projection.AggregateType, projection.AggregateID)
		if _, duplicate := byKey[key]; duplicate {
			return nil, nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "duplicate online projection"})
		}
		item := projectionInventoryItem{ProjectID: projection.ProjectID, AggregateType: projection.AggregateType, AggregateID: projection.AggregateID, Version: projection.Version, SHA256: digest}
		items = append(items, item)
		byKey[key] = item
	}
	sortInventory(items)
	return items, byKey, nil
}

func sortInventory(items []projectionInventoryItem) {
	sort.Slice(items, func(left, right int) bool {
		if items[left].AggregateType != items[right].AggregateType {
			return items[left].AggregateType < items[right].AggregateType
		}
		return items[left].AggregateID < items[right].AggregateID
	})
}

func inventoryDigest(items []projectionInventoryItem) (string, error) {
	payload, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(payload)
}

func reconciliationDigest(report ReconciliationReport) (string, error) {
	report.ReportSHA256 = ""
	payload, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(payload)
}

// Digest binds the complete snapshot, including its aggregate version.
func (s Snapshot) Digest() (string, error) {
	if s.Version < 1 || !json.Valid(s.State) {
		return "", aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "projection snapshot"})
	}
	payload, err := json.Marshal(struct {
		Version int64           `json:"version"`
		State   json.RawMessage `json:"state"`
	}{Version: s.Version, State: s.State})
	if err != nil {
		return "", fmt.Errorf("marshal projection snapshot: %w", err)
	}
	return canonicaljson.Digest(payload)
}
