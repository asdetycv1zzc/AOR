package eventing

import (
	"errors"
	"fmt"
	"strings"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/cloudevents"
)

var ErrExternalCorrelation = errors.New("external event correlation is incomplete")

type CloudEventOptions struct {
	Source      string
	Traceparent string
	Tracestate  string
	TaskID      string
	TaskReason  string
	AgentRunID  string
	AgentReason string
}

// Externalize turns an immutable internal event into the validated CloudEvents
// envelope used at the event-bus boundary. Missing scoped identities are
// represented by an explicit reason; trace context is always required.
func Externalize(event DomainEvent, options CloudEventOptions) (cloudevents.Event, error) {
	if event.EventID == "" || event.ProjectID == "" || event.Type == "" || event.OccurredAt.IsZero() || len(event.Payload) == 0 {
		return cloudevents.Event{}, ErrExternalCorrelation
	}
	if options.Traceparent == "" {
		options.Traceparent = event.Traceparent
		options.Tracestate = event.Tracestate
	}
	if options.TaskID == "" && options.TaskReason == "" {
		options.TaskID, options.TaskReason = event.TaskID, event.TaskIDReason
	}
	if options.AgentRunID == "" && options.AgentReason == "" {
		options.AgentRunID, options.AgentReason = event.AgentRunID, event.AgentRunReason
	}
	if options.Source == "" || options.Traceparent == "" {
		return cloudevents.Event{}, ErrExternalCorrelation
	}
	if event.PayloadSHA256 == "" {
		return cloudevents.Event{}, ErrExternalCorrelation
	}
	payloadDigest, err := canonicaljson.Digest(event.Payload)
	if err != nil || payloadDigest != event.PayloadSHA256 {
		return cloudevents.Event{}, fmt.Errorf("%w: payload digest mismatch", ErrExternalCorrelation)
	}
	if err := options.validate(); err != nil {
		return cloudevents.Event{}, err
	}
	taskID, taskReason := options.TaskID, options.TaskReason
	agentRunID, agentReason := options.AgentRunID, options.AgentReason
	subject := "projects/" + event.ProjectID
	switch event.AggregateType {
	case "task":
		if taskID != "" && taskID != event.AggregateID {
			return cloudevents.Event{}, fmt.Errorf("%w: task identity does not match aggregate", ErrExternalCorrelation)
		}
		taskID, taskReason = event.AggregateID, ""
		subject += "/tasks/" + event.AggregateID
	case "agent_run", "agent-run":
		if agentRunID != "" && agentRunID != event.AggregateID {
			return cloudevents.Event{}, fmt.Errorf("%w: agent run identity does not match aggregate", ErrExternalCorrelation)
		}
		agentRunID, agentReason = event.AggregateID, ""
		subject += "/agents/" + event.AggregateID
	case "audit":
		subject += "/audits/" + event.AggregateID
	case "approval":
		subject += "/approvals/" + event.AggregateID
	case "project", "goal", "goal_message", "goal_spec", "plan", "module", "spec_artifact", "budget", "knowledge", "":
	default:
		return cloudevents.Event{}, fmt.Errorf("%w: unsupported aggregate type", ErrExternalCorrelation)
	}
	if taskID == "" && taskReason == "" {
		taskReason = "NOT_CREATED"
	}
	if agentRunID == "" && agentReason == "" {
		agentReason = "NOT_CREATED"
	}
	dataSchema, found := cloudevents.Catalog[event.Type]
	if !found {
		return cloudevents.Event{}, fmt.Errorf("%w: event type is not catalogued", ErrExternalCorrelation)
	}
	external := cloudevents.Event{
		SpecVersion: "1.0", ID: event.EventID, Source: options.Source, Type: event.Type, Subject: subject, Time: event.OccurredAt,
		DataContentType: "application/json", DataSchema: dataSchema, Traceparent: options.Traceparent, Tracestate: options.Tracestate,
		ProjectID: event.ProjectID, TaskID: taskID, TaskIDReason: taskReason, AgentRunID: agentRunID, AgentRunReason: agentReason, Data: append([]byte(nil), event.Payload...),
	}
	if err := external.Validate(); err != nil {
		return cloudevents.Event{}, fmt.Errorf("%w: %v", ErrExternalCorrelation, err)
	}
	return external, nil
}

func (o CloudEventOptions) validate() error {
	if strings.ContainsAny(o.Source, "\r\n") || strings.ContainsAny(o.Traceparent, "\r\n") {
		return ErrExternalCorrelation
	}
	return nil
}
