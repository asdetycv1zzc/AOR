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
	EventID          string
	TenantID         string
	ProjectID        string
	AggregateType    string
	AggregateID      string
	AggregateVersion int64
	Type             string
	PayloadSHA256    string
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
	fingerprint, err := validateEvent(event)
	if err != nil {
		return nil, err
	}
	reducer := p.reducers[event.AggregateType]
	if reducer == nil {
		return nil, fmt.Errorf("no reducer for aggregate type %q", event.AggregateType)
	}
	if prior, exists := p.eventIDs[event.EventID]; exists {
		if prior == fingerprint {
			return nil, nil
		}
		return nil, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "eventId"})
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
	return eventFingerprint{
		EventID: event.EventID, TenantID: event.TenantID, ProjectID: event.ProjectID, AggregateType: event.AggregateType, AggregateID: event.AggregateID, AggregateVersion: event.AggregateVersion, Type: event.Type, PayloadSHA256: event.PayloadSHA256,
	}, nil
}

func aggregateKey(tenantID, aggregateType, aggregateID string) string {
	return tenantID + "\x00" + aggregateType + "\x00" + aggregateID
}

func cloneEvent(event eventing.DomainEvent) eventing.DomainEvent {
	event.Payload = cloneJSON(event.Payload)
	return event
}

func cloneJSON(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}
