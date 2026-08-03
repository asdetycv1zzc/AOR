package projection

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// Rebuild creates a new projector from the complete immutable event log for a
// tenant. The event log is sorted again so every implementation has identical
// replay behavior.
func Rebuild(ctx context.Context, log eventing.EventLog, tenantID string, reducers map[string]Reducer) (*Projector, error) {
	if log == nil || tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "projection rebuild"})
	}
	events, err := log.ListEvents(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list projection events: %w", err)
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
