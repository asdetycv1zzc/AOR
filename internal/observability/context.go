package observability

import (
	"fmt"
	"regexp"
)

type MissingReason string

const (
	ReasonNotApplicable    MissingReason = "NOT_APPLICABLE"
	ReasonNotCreated       MissingReason = "NOT_CREATED"
	ReasonUnavailable      MissingReason = "UNAVAILABLE"
	ReasonRedactedByPolicy MissingReason = "REDACTED_BY_POLICY"
)

type Correlation struct {
	ProjectID        string        `json:"project_id"`
	ProjectIDReason  MissingReason `json:"project_id_empty_reason"`
	WorkflowID       string        `json:"workflow_id"`
	WorkflowIDReason MissingReason `json:"workflow_id_empty_reason"`
	TaskID           string        `json:"task_id"`
	TaskIDReason     MissingReason `json:"task_id_empty_reason"`
	AgentRunID       string        `json:"agent_run_id"`
	AgentRunIDReason MissingReason `json:"agent_run_id_empty_reason"`
}

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func (c Correlation) Validate() error {
	checks := []struct {
		name   string
		value  string
		reason MissingReason
	}{
		{name: "project_id", value: c.ProjectID, reason: c.ProjectIDReason},
		{name: "workflow_id", value: c.WorkflowID, reason: c.WorkflowIDReason},
		{name: "task_id", value: c.TaskID, reason: c.TaskIDReason},
		{name: "agent_run_id", value: c.AgentRunID, reason: c.AgentRunIDReason},
	}
	for _, check := range checks {
		if check.value != "" {
			if check.reason != "" || !opaqueIDPattern.MatchString(check.value) {
				return fmt.Errorf("%w: %s has an invalid identifier or a conflicting empty reason", ErrInvalidCorrelation, check.name)
			}
			continue
		}
		if !validMissingReason(check.reason) {
			return fmt.Errorf("%w: %s requires an explicit empty reason", ErrInvalidCorrelation, check.name)
		}
	}
	return nil
}

func validMissingReason(reason MissingReason) bool {
	switch reason {
	case ReasonNotApplicable, ReasonNotCreated, ReasonUnavailable, ReasonRedactedByPolicy:
		return true
	default:
		return false
	}
}

func (c Correlation) traceAttributes() map[string]string {
	attributes := map[string]string{}
	addCorrelationAttribute(attributes, "aor.project.id", c.ProjectID, c.ProjectIDReason)
	addCorrelationAttribute(attributes, "aor.workflow.id", c.WorkflowID, c.WorkflowIDReason)
	addCorrelationAttribute(attributes, "aor.task.id", c.TaskID, c.TaskIDReason)
	addCorrelationAttribute(attributes, "aor.agent.run.id", c.AgentRunID, c.AgentRunIDReason)
	return attributes
}

func addCorrelationAttribute(attributes map[string]string, key, value string, reason MissingReason) {
	if value != "" {
		attributes[key] = value
		return
	}
	attributes[key+".empty_reason"] = string(reason)
}
