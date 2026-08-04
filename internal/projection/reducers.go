package projection

import (
	"encoding/json"
	"fmt"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func StateReducer(_ json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error) {
	if len(event.ReplayState) != 0 || event.ReplayStateSHA256 != "" {
		return AuthoritativeStateReducer(nil, event)
	}
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

func AuthoritativeStateReducer(_ json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(event.ReplayState, &object) != nil || object == nil || event.ReplayStateSHA256 == "" {
		return nil, fmt.Errorf("event has no authoritative replay state")
	}
	digest, err := canonicaljson.Digest(event.ReplayState)
	if err != nil || digest != event.ReplayStateSHA256 {
		return nil, fmt.Errorf("authoritative replay state digest mismatch")
	}
	return append(json.RawMessage(nil), event.ReplayState...), nil
}
