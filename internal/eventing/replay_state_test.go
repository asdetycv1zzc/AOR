package eventing

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func TestDeriveReplayStateSupportsLegacyImmutableEvents(t *testing.T) {
	wrapped := json.RawMessage(`{"tenantId":"tenant-1","projectId":"project-1","aggregateVersion":1,"projection":{"tenantId":"tenant-1","projectId":"project-1","id":"project-1","version":1}}`)
	event := DomainEvent{EventID: "event-1", TenantID: "tenant-1", ProjectID: "project-1", AggregateType: "project", AggregateID: "project-1", AggregateVersion: 1, Payload: wrapped}
	derived, err := deriveReplayState(event, nil)
	if err != nil || len(derived.ReplayState) == 0 || derived.ReplayStateSHA256 == "" {
		t.Fatalf("wrapped replay state = %#v error=%v", derived, err)
	}

	payload := json.RawMessage(`{"tenantId":"tenant-1","projectId":"project-1","kind":"PLAN_SPEC","specId":"plan-1","version":1,"contentSha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111","artifactSha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222","uri":"artifact://sha256/2222222222222222222222222222222222222222222222222222222222222222"}`)
	state := json.RawMessage(`{"tenantId":"tenant-1","projectId":"project-1","kind":"PLAN_SPEC","specId":"plan-1","version":1,"contentSha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111","artifactSha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222","uri":"artifact://sha256/2222222222222222222222222222222222222222222222222222222222222222","mediaType":"application/json","createdBy":"agent-plan"}`)
	resultDigest, err := canonicaljson.Digest(state)
	if err != nil {
		t.Fatal(err)
	}
	artifact := DomainEvent{EventID: "event-2", TenantID: "tenant-1", ProjectID: "project-1", AggregateType: "spec_artifact", AggregateID: legacyArtifactAggregateID("project-1", "PLAN_SPEC", "plan-1", 1), AggregateVersion: 1, Payload: payload}
	derived, err = deriveReplayState(artifact, []replayResultCandidate{{EventIDs: []string{"event-2"}, Result: state, ResultSHA256: resultDigest}})
	if err != nil || string(derived.ReplayState) != string(state) {
		t.Fatalf("artifact replay state = %#v error=%v", derived, err)
	}
	artifact.AggregateID = "wrong"
	if _, err := deriveReplayState(artifact, []replayResultCandidate{{EventIDs: []string{"event-2"}, Result: state, ResultSHA256: resultDigest}}); err == nil {
		t.Fatal("legacy artifact accepted a mismatched aggregate identity")
	}
}

func TestDeriveReplayStateRejectsUnknownLegacyAggregate(t *testing.T) {
	state := json.RawMessage(`{"tenantId":"tenant-1","projectId":"project-1","id":"aggregate-1","version":1}`)
	digest, err := canonicaljson.Digest(state)
	if err != nil {
		t.Fatal(err)
	}
	event := DomainEvent{
		EventID: "event-unknown", TenantID: "tenant-1", ProjectID: "project-1",
		AggregateType: "unknown", AggregateID: "aggregate-1", AggregateVersion: 1, Payload: state,
	}
	if _, err := deriveReplayState(event, []replayResultCandidate{{
		EventIDs: []string{event.EventID}, Result: state, ResultSHA256: digest,
	}}); !errors.Is(err, ErrReplayStateUnavailable) {
		t.Fatalf("unknown legacy aggregate error=%v", err)
	}
}

func TestDeriveReplayStateSupportsBudgetAdjustmentSnapshots(t *testing.T) {
	state := json.RawMessage(`{"tenantId":"tenant-1","projectId":"project-1","accountId":"account-1","principalId":"admin","previousVersion":4,"aggregateVersion":5,"version":5,"hardLimitMinor":200,"softLimitMinor":150,"currency":"USD","reason":"approved"}`)
	event := DomainEvent{EventID: "event-budget", TenantID: "tenant-1", ProjectID: "project-1", AggregateType: "budget", AggregateID: "account-1", AggregateVersion: 5, Type: "io.aor.budget.adjusted.v1", Payload: state}
	derived, err := deriveReplayState(event, nil)
	if err != nil || string(derived.ReplayState) != string(state) || derived.ReplayStateSHA256 == "" {
		t.Fatalf("budget replay state = %#v error=%v", derived, err)
	}
	event.AggregateVersion = 6
	if _, err := deriveReplayState(event, nil); !errors.Is(err, ErrReplayStateUnavailable) {
		t.Fatalf("mismatched budget version error=%v", err)
	}
}
