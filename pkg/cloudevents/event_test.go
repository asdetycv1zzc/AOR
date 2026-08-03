package cloudevents

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventValidatesCatalogAndAggregateData(t *testing.T) {
	event := validEvent()
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEventRejectsSchemaConfusion(t *testing.T) {
	event := validEvent()
	event.DataSchema = "https://schemas.aor.local/events/wrong.v1.schema.json"
	if err := event.Validate(); err == nil {
		t.Fatal("event accepted a mismatched data schema")
	}
}

func TestEventRejectsMissingAggregateVersion(t *testing.T) {
	event := validEvent()
	event.Data = json.RawMessage(`{"projectId":"prj_1"}`)
	if err := event.Validate(); err == nil {
		t.Fatal("event accepted missing aggregate version")
	}
}

func TestEventRejectsMissingOrMismatchedCorrelation(t *testing.T) {
	event := validEvent()
	event.TaskIDReason = ""
	if err := event.Validate(); err == nil {
		t.Fatal("event accepted an unexplained missing task")
	}
	event = validEvent()
	event.ProjectID = "another-project"
	if err := event.Validate(); err == nil {
		t.Fatal("event accepted mismatched project correlation")
	}
	event = validEvent()
	event.Traceparent = "00-00000000000000000000000000000000-0000000000000000-01"
	if err := event.Validate(); err == nil {
		t.Fatal("event accepted an all-zero trace context")
	}
}

func validEvent() Event {
	return Event{
		SpecVersion:     "1.0",
		ID:              "evt_1",
		Source:          "urn:aor:service:orchestrator",
		Type:            "io.aor.project.created.v1",
		Subject:         "projects/prj_1",
		Time:            time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		DataContentType: "application/json",
		DataSchema:      "https://schemas.aor.local/events/project-created.v1.schema.json",
		Traceparent:     "00-00000000000000000000000000000001-0000000000000001-01",
		ProjectID:       "prj_1",
		TaskIDReason:    "NOT_CREATED",
		AgentRunReason:  "NOT_CREATED",
		Data:            json.RawMessage(`{"projectId":"prj_1","aggregateVersion":1}`),
	}
}
