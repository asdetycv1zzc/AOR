package eventing

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestExternalizeRequiresTraceAndScopedReasons(t *testing.T) {
	event := externalEvent("project", "io.aor.project.created.v1", `{"projectId":"project-1","aggregateVersion":1}`)
	external, err := Externalize(event, CloudEventOptions{Source: "urn:aor:service:orchestrator", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	if err != nil {
		t.Fatal(err)
	}
	if external.ProjectID != "project-1" || external.TaskIDReason != "NOT_CREATED" || external.AgentRunReason != "NOT_CREATED" {
		t.Fatalf("missing correlation reasons: %#v", external)
	}
	if _, err := Externalize(event, CloudEventOptions{Source: "urn:aor:service:orchestrator"}); !errors.Is(err, ErrExternalCorrelation) {
		t.Fatalf("missing trace result = %v", err)
	}
}

func TestExternalizeDerivesTaskSubjectAndRejectsMismatch(t *testing.T) {
	event := externalEvent("task", "io.aor.module.defined.v1", `{"projectId":"project-1","aggregateVersion":2}`)
	external, err := Externalize(event, CloudEventOptions{Source: "urn:aor:service:orchestrator", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	if err != nil {
		t.Fatal(err)
	}
	if external.Subject != "projects/project-1/tasks/task-1" || external.TaskID != "task-1" || external.TaskIDReason != "" {
		t.Fatalf("task correlation was not propagated: %#v", external)
	}
	_, err = Externalize(event, CloudEventOptions{Source: "urn:aor:service:orchestrator", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", TaskID: "other-task"})
	if err == nil {
		t.Fatal("mismatched task correlation was accepted")
	}
}

func externalEvent(aggregateType, eventType, payload string) DomainEvent {
	return DomainEvent{EventID: "evt_1", TenantID: "tenant-1", ProjectID: "project-1", AggregateType: aggregateType, AggregateID: "task-1", AggregateVersion: 1, Type: eventType, Payload: json.RawMessage(payload), OccurredAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}
