package aop

import (
	"encoding/json"
	"testing"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestUnknownIntentFailsClosed(t *testing.T) {
	envelope := validEnvelope(Intent("INVENT_WORK"))
	if err := envelope.Validate(time.Now().UTC()); err == nil || err.Code != aorerrors.CodeInvalidArgument {
		t.Fatalf("expected invalid argument, got %#v", err)
	}
}

func TestGoalIntentRejectsPlanAndTaskReferences(t *testing.T) {
	envelope := validEnvelope(IntentProposeGoal)
	envelope.PlanSpec = validSpecRef()
	envelope.TaskID = "task_1"
	if err := envelope.Validate(time.Now().UTC()); err == nil {
		t.Fatal("goal intent accepted later-stage references")
	}
}

func TestSubmissionRequiresAllImmutableReferences(t *testing.T) {
	envelope := validEnvelope(IntentSubmitImplementation)
	envelope.PlanSpec = nil
	if err := envelope.Validate(time.Now().UTC()); err == nil {
		t.Fatal("submission accepted without PlanSpec")
	}
}

func TestUnknownOptionalJSONFieldIsIgnored(t *testing.T) {
	raw := []byte(`{"aopVersion":"1.0","messageId":"msg_1","idempotencyKey":"idem_1","correlationId":"corr_1","projectId":"prj_1","goalSpec":{"version":1,"sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"sender":{"agentInstanceId":"agt_1","role":"GOAL","leaseId":"lease_1"},"scope":"PROJECT","intent":"PROPOSE_GOAL","expectedAggregateVersion":0,"artifactRefs":[],"knowledgeRefs":[],"createdAt":"2030-01-01T00:00:00Z","expiresAt":"2030-01-01T00:10:00Z","futureOptionalField":{"enabled":true}}`)
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Validate(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("optional field broke old consumer: %v", err)
	}
}

func TestEveryDeclaredIntentHasAValidReferenceShape(t *testing.T) {
	for _, intent := range Intents() {
		envelope := validEnvelope(intent)
		if intent == IntentRequestUserDecision {
			envelope.Attempt = 3
		}
		if err := envelope.Validate(time.Now().UTC()); err != nil {
			t.Errorf("%s: %v", intent, err)
		}
	}
}

func validEnvelope(intent Intent) Envelope {
	now := time.Now().UTC()
	envelope := Envelope{
		AOPVersion: "1.0", MessageID: "msg_1", IdempotencyKey: "idem_1", CorrelationID: "corr_1", ProjectID: "prj_1",
		GoalSpec: validSpecRef(), Sender: Sender{AgentInstanceID: "agt_1", Role: "EXECUTOR", LeaseID: "lease_1"}, Scope: ScopeProject,
		Intent: intent, ExpectedAggregateVersion: 0, ArtifactRefs: []string{}, KnowledgeRefs: []string{}, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if requirements, exists := intentRequirements[intent]; exists {
		if requirements.plan {
			envelope.PlanSpec = validSpecRef()
		}
		if requirements.module {
			envelope.ModuleSpec = validSpecRef()
			envelope.TaskID = "task_1"
			envelope.Scope = ScopeTask
		}
		if requirements.attempt {
			envelope.AttemptSeriesID = "series_1"
			envelope.Attempt = 1
		}
	}
	return envelope
}

func validSpecRef() *SpecRef {
	return &SpecRef{Version: 1, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
}
