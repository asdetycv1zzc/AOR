package projection

import (
	"encoding/json"
	"fmt"

	"github.com/akimisaka/aor/internal/eventing"
)

func StateReducer(_ json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error) {
	var payload struct {
		TenantID         string          `json:"tenantId"`
		ProjectID        string          `json:"projectId"`
		AggregateVersion int64           `json:"aggregateVersion"`
		Projection       json.RawMessage `json:"projection"`
	}
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return nil, fmt.Errorf("decode state event payload: %w", err)
	}
	if payload.TenantID != event.TenantID || payload.ProjectID != event.ProjectID || payload.AggregateVersion != event.AggregateVersion || !json.Valid(payload.Projection) {
		return nil, fmt.Errorf("state event payload does not match its envelope")
	}
	var version struct {
		Version int64 `json:"version"`
	}
	if err := json.Unmarshal(payload.Projection, &version); err != nil || version.Version != event.AggregateVersion {
		return nil, fmt.Errorf("state projection version does not match event")
	}
	return append(json.RawMessage(nil), payload.Projection...), nil
}
