package eventing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

var (
	ErrReplayStateUnavailable    = errors.New("authoritative replay state is unavailable")
	ErrRelationalProjectionDrift = errors.New("relational projection differs from authoritative aggregate state")
)

type replayResultCandidate struct {
	EventIDs     []string
	Result       json.RawMessage
	ResultSHA256 string
}

func bindReplayStates(events []DomainEvent, updates []ProjectionUpdate) ([]DomainEvent, error) {
	states := make(map[string]json.RawMessage, len(updates))
	for _, update := range updates {
		states[aggregateKey(update.TenantID, update.AggregateType, update.AggregateID)] = update.State
	}
	bound := make([]DomainEvent, len(events))
	for index, event := range events {
		state, found := states[aggregateKey(event.TenantID, event.AggregateType, event.AggregateID)]
		if !found {
			return nil, fmt.Errorf("%w: event %s has no projection update", ErrReplayStateUnavailable, event.EventID)
		}
		var err error
		bound[index], err = bindReplayState(event, state)
		if err != nil {
			return nil, err
		}
	}
	return bound, nil
}

func bindReplayState(event DomainEvent, state json.RawMessage) (DomainEvent, error) {
	if !jsonObject(state) {
		return DomainEvent{}, fmt.Errorf("%w: event %s state is not an object", ErrReplayStateUnavailable, event.EventID)
	}
	digest, err := canonicaljson.Digest(state)
	if err != nil {
		return DomainEvent{}, fmt.Errorf("%w: event %s state digest: %v", ErrReplayStateUnavailable, event.EventID, err)
	}
	event.ReplayState = cloneJSON(state)
	event.ReplayStateSHA256 = digest
	return event, nil
}

func deriveReplayState(event DomainEvent, candidates []replayResultCandidate) (DomainEvent, error) {
	if state, found := wrappedReplayState(event); found {
		return bindReplayState(event, state)
	}
	if rawReplayStateMatches(event, event.Payload) {
		return bindReplayState(event, event.Payload)
	}
	if len(candidates) != 1 {
		return DomainEvent{}, fmt.Errorf("%w: event %s is bound to %d command results", ErrReplayStateUnavailable, event.EventID, len(candidates))
	}
	candidate := candidates[0]
	if !containsEventID(candidate.EventIDs, event.EventID) {
		return DomainEvent{}, fmt.Errorf("%w: event %s command binding is incomplete", ErrReplayStateUnavailable, event.EventID)
	}
	resultDigest, err := canonicaljson.Digest(candidate.Result)
	if err != nil || resultDigest != candidate.ResultSHA256 {
		return DomainEvent{}, fmt.Errorf("%w: event %s command result digest mismatch", ErrReplayStateUnavailable, event.EventID)
	}
	if resultReplayStateMatches(event, candidate.Result) {
		return bindReplayState(event, candidate.Result)
	}
	return DomainEvent{}, fmt.Errorf("%w: event %s payload cannot rebuild aggregate %s/%s", ErrReplayStateUnavailable, event.EventID, event.AggregateType, event.AggregateID)
}

func wrappedReplayState(event DomainEvent) (json.RawMessage, bool) {
	var envelope struct {
		TenantID         string          `json:"tenantId"`
		ProjectID        string          `json:"projectId"`
		AggregateVersion int64           `json:"aggregateVersion"`
		Projection       json.RawMessage `json:"projection"`
	}
	if json.Unmarshal(event.Payload, &envelope) != nil || len(envelope.Projection) == 0 {
		return nil, false
	}
	if envelope.TenantID != event.TenantID || envelope.ProjectID != event.ProjectID || envelope.AggregateVersion != event.AggregateVersion || !jsonObject(envelope.Projection) {
		return nil, false
	}
	return envelope.Projection, true
}

func rawReplayStateMatches(event DomainEvent, state json.RawMessage) bool {
	if !jsonObject(state) {
		return false
	}
	var identity struct {
		TenantID   string `json:"tenantId"`
		ProjectID  string `json:"projectId"`
		ID         string `json:"id"`
		Version    int64  `json:"version"`
		GoalSpecID string `json:"goalSpecId"`
		RecordID   string `json:"recordId"`
		Spec       struct {
			Content struct {
				Version int `json:"version"`
			} `json:"content"`
		} `json:"spec"`
	}
	if json.Unmarshal(state, &identity) != nil || identity.TenantID != event.TenantID || identity.ProjectID != event.ProjectID {
		return false
	}
	switch event.AggregateType {
	case "project", "task":
		return identity.ID == event.AggregateID && identity.Version == event.AggregateVersion
	case "goal_message":
		return event.AggregateVersion == 1 && identity.ID == event.AggregateID
	case "goal_spec":
		return identity.GoalSpecID != "" && identity.RecordID != "" && identity.Spec.Content.Version > 0 &&
			event.AggregateID == legacyGoalSpecAggregateID(event.ProjectID, identity.GoalSpecID, identity.Spec.Content.Version)
	case "spec_artifact":
		return false
	default:
		return false
	}
}

func resultReplayStateMatches(event DomainEvent, result json.RawMessage) bool {
	if rawReplayStateMatches(event, result) {
		return true
	}
	if event.AggregateType != "spec_artifact" || !jsonObject(result) {
		return false
	}
	var payload struct {
		TenantID       string `json:"tenantId"`
		ProjectID      string `json:"projectId"`
		Kind           string `json:"kind"`
		SpecID         string `json:"specId"`
		Version        int    `json:"version"`
		ContentSHA256  string `json:"contentSha256"`
		ArtifactSHA256 string `json:"artifactSha256"`
		URI            string `json:"uri"`
	}
	var state struct {
		TenantID       string `json:"tenantId"`
		ProjectID      string `json:"projectId"`
		Kind           string `json:"kind"`
		SpecID         string `json:"specId"`
		Version        int    `json:"version"`
		ContentSHA256  string `json:"contentSha256"`
		ArtifactSHA256 string `json:"artifactSha256"`
		URI            string `json:"uri"`
		MediaType      string `json:"mediaType"`
		CreatedBy      string `json:"createdBy"`
	}
	if json.Unmarshal(event.Payload, &payload) != nil || json.Unmarshal(result, &state) != nil {
		return false
	}
	return payload.TenantID == event.TenantID && payload.ProjectID == event.ProjectID &&
		state.TenantID == payload.TenantID && state.ProjectID == payload.ProjectID &&
		state.Kind == payload.Kind && state.SpecID == payload.SpecID && state.Version == payload.Version &&
		state.ContentSHA256 == payload.ContentSHA256 && state.ArtifactSHA256 == payload.ArtifactSHA256 &&
		state.URI == payload.URI && state.MediaType != "" && state.CreatedBy != "" &&
		event.AggregateID == legacyArtifactAggregateID(event.ProjectID, payload.Kind, payload.SpecID, payload.Version)
}

func legacyGoalSpecAggregateID(projectID, goalSpecID string, version int) string {
	digest := sha256.Sum256([]byte(projectID + "\x00" + goalSpecID + "\x00" + fmt.Sprint(version)))
	return "goal_" + hex.EncodeToString(digest[:16])
}

func legacyArtifactAggregateID(projectID, kind, specID string, version int) string {
	digest := sha256.Sum256([]byte(projectID + "\x00" + kind + "\x00" + specID + "\x00" + fmt.Sprint(version)))
	return hex.EncodeToString(digest[:])
}

func containsEventID(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func jsonObject(value json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(value, &object) == nil && object != nil
}
