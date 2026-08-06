package projection

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const maxPendingPerAggregate = 10000

type Reducer func(current json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error)

type Snapshot struct {
	Version int64
	State   json.RawMessage
}

type eventFingerprint struct {
	EventID           string
	TenantID          string
	ProjectID         string
	AggregateType     string
	AggregateID       string
	AggregateVersion  int64
	Type              string
	PayloadSHA256     string
	ReplayStateSHA256 string
}

type stream struct {
	version int64
	state   json.RawMessage
	pending map[int64]eventing.DomainEvent
	applied map[int64]eventFingerprint
}

type Projector struct {
	mu       sync.Mutex
	reducers map[string]Reducer
	streams  map[string]*stream
	eventIDs map[string]eventFingerprint
}

func New(reducers map[string]Reducer) *Projector {
	copyReducers := make(map[string]Reducer, len(reducers))
	for key, reducer := range reducers {
		copyReducers[key] = reducer
	}
	return &Projector{reducers: copyReducers, streams: make(map[string]*stream), eventIDs: make(map[string]eventFingerprint)}
}

func (p *Projector) Apply(event eventing.DomainEvent) ([]eventing.DomainEvent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if event.AggregateType == "budget" && len(event.ReplayState) == 0 {
		digest, digestErr := canonicaljson.Digest(event.Payload)
		if digestErr != nil {
			return nil, digestErr
		}
		event.ReplayState = cloneJSON(event.Payload)
		event.ReplayStateSHA256 = digest
	}
	fingerprint, err := validateEvent(event)
	if err != nil {
		return nil, err
	}
	if prior, exists := p.eventIDs[event.EventID]; exists {
		if prior == fingerprint {
			return nil, nil
		}
		return nil, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "eventId"})
	}
	if event.AggregateType == "budget" {
		return p.applyBudgetSnapshotLocked(event, fingerprint)
	}
	reducer := p.reducers[event.AggregateType]
	if reducer == nil {
		return nil, fmt.Errorf("no reducer for aggregate type %q", event.AggregateType)
	}
	key := aggregateKey(event.TenantID, event.AggregateType, event.AggregateID)
	current := p.streams[key]
	if current == nil {
		current = &stream{pending: make(map[int64]eventing.DomainEvent), applied: make(map[int64]eventFingerprint)}
		p.streams[key] = current
	}
	if event.AggregateVersion <= current.version {
		if prior, exists := current.applied[event.AggregateVersion]; exists && prior == fingerprint {
			p.eventIDs[event.EventID] = fingerprint
			return nil, nil
		}
		return nil, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "aggregateVersion"})
	}
	if prior, exists := current.pending[event.AggregateVersion]; exists {
		priorFingerprint, priorErr := validateEvent(prior)
		if priorErr == nil && priorFingerprint == fingerprint {
			p.eventIDs[event.EventID] = fingerprint
			return nil, nil
		}
		return nil, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "pending aggregateVersion"})
	}
	if len(current.pending) >= maxPendingPerAggregate && event.AggregateVersion != current.version+1 {
		return nil, aorerrors.New(aorerrors.CodeRateLimited, event.CorrelationID, map[string]any{"limit": maxPendingPerAggregate, "scope": "projection gap"})
	}
	p.eventIDs[event.EventID] = fingerprint
	current.pending[event.AggregateVersion] = cloneEvent(event)

	var applied []eventing.DomainEvent
	for {
		next, exists := current.pending[current.version+1]
		if !exists {
			break
		}
		nextState, reduceErr := reducer(cloneJSON(current.state), cloneEvent(next))
		if reduceErr != nil {
			delete(current.pending, next.AggregateVersion)
			delete(p.eventIDs, next.EventID)
			return nil, fmt.Errorf("apply aggregate %s version %d: %w", key, next.AggregateVersion, reduceErr)
		}
		if !json.Valid(nextState) {
			delete(current.pending, next.AggregateVersion)
			delete(p.eventIDs, next.EventID)
			return nil, fmt.Errorf("reducer returned invalid JSON")
		}
		current.version = next.AggregateVersion
		current.state = cloneJSON(nextState)
		current.applied[next.AggregateVersion], _ = validateEvent(next)
		delete(current.pending, next.AggregateVersion)
		applied = append(applied, cloneEvent(next))
	}
	return applied, nil
}

// Budget account versions also advance for reservations and settlements that
// are intentionally not domain events. Budget adjustment events therefore
// carry complete snapshots and may contain version gaps; the newest verified
// snapshot is authoritative for this aggregate type.
func (p *Projector) applyBudgetSnapshotLocked(event eventing.DomainEvent, fingerprint eventFingerprint) ([]eventing.DomainEvent, error) {
	if event.Type != "io.aor.budget.adjusted.v1" || len(event.ReplayState) == 0 {
		return nil, fmt.Errorf("budget event has no authoritative snapshot")
	}
	if _, err := AuthoritativeStateReducer(nil, event); err != nil {
		return nil, err
	}
	var snapshot struct {
		TenantID         string `json:"tenantId"`
		ProjectID        string `json:"projectId"`
		AccountID        string `json:"accountId"`
		PrincipalID      string `json:"principalId"`
		PreviousVersion  int64  `json:"previousVersion"`
		AggregateVersion int64  `json:"aggregateVersion"`
		Version          int64  `json:"version"`
		HardLimit        int64  `json:"hardLimitMinor"`
		SoftLimit        int64  `json:"softLimitMinor"`
		Currency         string `json:"currency"`
		Reason           string `json:"reason"`
	}
	if json.Unmarshal(event.ReplayState, &snapshot) != nil || snapshot.TenantID != event.TenantID || snapshot.ProjectID != event.ProjectID || snapshot.AccountID != event.AggregateID || snapshot.PrincipalID == "" || snapshot.PreviousVersion < 1 || snapshot.AggregateVersion != event.AggregateVersion || snapshot.Version != event.AggregateVersion || snapshot.PreviousVersion+1 != snapshot.Version || snapshot.HardLimit < 0 || snapshot.SoftLimit < 0 || snapshot.SoftLimit > snapshot.HardLimit || len(snapshot.Currency) != 3 || snapshot.Currency[0] < 'A' || snapshot.Currency[0] > 'Z' || snapshot.Currency[1] < 'A' || snapshot.Currency[1] > 'Z' || snapshot.Currency[2] < 'A' || snapshot.Currency[2] > 'Z' || snapshot.Reason == "" {
		return nil, fmt.Errorf("budget event snapshot identity is invalid")
	}
	key := aggregateKey(event.TenantID, event.AggregateType, event.AggregateID)
	current := p.streams[key]
	if current == nil {
		current = &stream{pending: make(map[int64]eventing.DomainEvent), applied: make(map[int64]eventFingerprint)}
		p.streams[key] = current
	}
	if prior, exists := current.applied[event.AggregateVersion]; exists {
		if prior == fingerprint {
			p.eventIDs[event.EventID] = fingerprint
			return nil, nil
		}
		return nil, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "aggregateVersion"})
	}
	p.eventIDs[event.EventID] = fingerprint
	current.applied[event.AggregateVersion] = fingerprint
	if event.AggregateVersion <= current.version {
		return nil, nil
	}
	current.version = event.AggregateVersion
	current.state = cloneJSON(event.ReplayState)
	return []eventing.DomainEvent{cloneEvent(event)}, nil
}

func (p *Projector) Snapshot(tenantID, aggregateType, aggregateID string) (Snapshot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.streams[aggregateKey(tenantID, aggregateType, aggregateID)]
	if current == nil || current.version == 0 {
		return Snapshot{}, false
	}
	return Snapshot{Version: current.version, State: cloneJSON(current.state)}, true
}

func (p *Projector) ensureComplete() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, current := range p.streams {
		if len(current.pending) != 0 {
			return fmt.Errorf("incomplete event stream %q after version %d", key, current.version)
		}
	}
	return nil
}

func validateEvent(event eventing.DomainEvent) (eventFingerprint, error) {
	if event.EventID == "" || event.TenantID == "" || event.ProjectID == "" || event.AggregateType == "" || event.AggregateID == "" || event.AggregateVersion < 1 || event.Type == "" || len(event.Payload) == 0 {
		return eventFingerprint{}, aorerrors.New(aorerrors.CodeInvalidArgument, event.CorrelationID, map[string]any{"scope": "projection event"})
	}
	digest, err := canonicaljson.Digest(event.Payload)
	if err != nil || digest != event.PayloadSHA256 {
		return eventFingerprint{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, event.CorrelationID, map[string]any{"scope": "event payload"})
	}
	if (len(event.ReplayState) == 0) != (event.ReplayStateSHA256 == "") {
		return eventFingerprint{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, event.CorrelationID, map[string]any{"scope": "event replay state"})
	}
	if len(event.ReplayState) != 0 {
		replayDigest, replayErr := canonicaljson.Digest(event.ReplayState)
		if replayErr != nil || replayDigest != event.ReplayStateSHA256 {
			return eventFingerprint{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, event.CorrelationID, map[string]any{"scope": "event replay state"})
		}
	}
	return eventFingerprint{
		EventID: event.EventID, TenantID: event.TenantID, ProjectID: event.ProjectID, AggregateType: event.AggregateType, AggregateID: event.AggregateID, AggregateVersion: event.AggregateVersion, Type: event.Type, PayloadSHA256: event.PayloadSHA256, ReplayStateSHA256: event.ReplayStateSHA256,
	}, nil
}

func aggregateKey(tenantID, aggregateType, aggregateID string) string {
	return tenantID + "\x00" + aggregateType + "\x00" + aggregateID
}

func cloneEvent(event eventing.DomainEvent) eventing.DomainEvent {
	event.Payload = cloneJSON(event.Payload)
	event.ReplayState = cloneJSON(event.ReplayState)
	return event
}

func cloneJSON(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}
