// Package cloudevents defines the AOR CloudEvents 1.0 profile.
package cloudevents

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const SpecVersion = "1.0"

type Event struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject"`
	Time            time.Time       `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	DataSchema      string          `json:"dataschema"`
	Traceparent     string          `json:"traceparent"`
	Tracestate      string          `json:"tracestate,omitempty"`
	ProjectID       string          `json:"aorprojectid"`
	TaskID          string          `json:"aortaskid,omitempty"`
	TaskIDReason    string          `json:"aortaskidreason,omitempty"`
	AgentRunID      string          `json:"aoragentrunid,omitempty"`
	AgentRunReason  string          `json:"aoragentrunidreason,omitempty"`
	Data            json.RawMessage `json:"data"`
}

var (
	typePattern        = regexp.MustCompile(`^io\.aor\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.v[1-9][0-9]*$`)
	subjectPattern     = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+(?:/(?:tasks|agents|audits|approvals)/[A-Za-z0-9_-]+)?$`)
	traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
	opaqueIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

var Catalog = map[string]string{
	"io.aor.project.created.v1":                   "https://schemas.aor.local/events/project-created.v1.schema.json",
	"io.aor.goal.proposed.v1":                     "https://schemas.aor.local/events/goal-proposed.v1.schema.json",
	"io.aor.goal.approved.v1":                     "https://schemas.aor.local/events/goal-approved.v1.schema.json",
	"io.aor.goal.superseded.v1":                   "https://schemas.aor.local/events/goal-superseded.v1.schema.json",
	"io.aor.plan.published.v1":                    "https://schemas.aor.local/events/plan-published.v1.schema.json",
	"io.aor.module.defined.v1":                    "https://schemas.aor.local/events/module-defined.v1.schema.json",
	"io.aor.module.execution-leased.v1":           "https://schemas.aor.local/events/module-execution-leased.v1.schema.json",
	"io.aor.module.implementation-submitted.v1":   "https://schemas.aor.local/events/module-implementation-submitted.v1.schema.json",
	"io.aor.module.deterministic-audit-passed.v1": "https://schemas.aor.local/events/module-deterministic-audit-passed.v1.schema.json",
	"io.aor.module.deterministic-audit-failed.v1": "https://schemas.aor.local/events/module-deterministic-audit-failed.v1.schema.json",
	"io.aor.module.llm-audit-passed.v1":           "https://schemas.aor.local/events/module-llm-audit-passed.v1.schema.json",
	"io.aor.module.llm-audit-failed.v1":           "https://schemas.aor.local/events/module-llm-audit-failed.v1.schema.json",
	"io.aor.module.blocked-user-decision.v1":      "https://schemas.aor.local/events/module-blocked-user-decision.v1.schema.json",
	"io.aor.module.integrated.v1":                 "https://schemas.aor.local/events/module-integrated.v1.schema.json",
	"io.aor.approval.committed.v1":                "https://schemas.aor.local/events/approval-committed.v1.schema.json",
	"io.aor.project.completed.v1":                 "https://schemas.aor.local/events/project-completed.v1.schema.json",
}

func (e Event) Validate() error {
	if e.SpecVersion != SpecVersion || e.ID == "" || e.DataContentType != "application/json" || e.Time.IsZero() {
		return fmt.Errorf("required CloudEvents attributes are invalid")
	}
	if !typePattern.MatchString(e.Type) {
		return fmt.Errorf("invalid AOR event type")
	}
	expectedSchema, known := Catalog[e.Type]
	if !known || e.DataSchema != expectedSchema {
		return fmt.Errorf("event type and data schema do not match the catalog")
	}
	if !subjectPattern.MatchString(e.Subject) || !validTraceContext(e.Traceparent, e.Tracestate) {
		return fmt.Errorf("event subject or trace context is invalid")
	}
	if !opaqueIDPattern.MatchString(e.ProjectID) || !validScopedID(e.TaskID, e.TaskIDReason) || !validScopedID(e.AgentRunID, e.AgentRunReason) {
		return fmt.Errorf("event correlation context is invalid")
	}
	source, err := url.Parse(e.Source)
	if err != nil || source.Scheme == "" {
		return fmt.Errorf("event source must be an absolute URI")
	}
	schema, err := url.Parse(e.DataSchema)
	if err != nil || schema.Scheme != "https" {
		return fmt.Errorf("event data schema must be an HTTPS URI")
	}
	var data struct {
		ProjectID        string `json:"projectId"`
		AggregateVersion int64  `json:"aggregateVersion"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil || data.ProjectID == "" || data.ProjectID != e.ProjectID || data.AggregateVersion < 1 {
		return fmt.Errorf("event data must identify a project and positive aggregate version")
	}
	parts := strings.Split(e.Subject, "/")
	if len(parts) < 2 || parts[1] != e.ProjectID {
		return fmt.Errorf("event subject and project correlation do not match")
	}
	if len(parts) == 4 && (parts[2] == "tasks" && parts[3] != e.TaskID || parts[2] == "agents" && parts[3] != e.AgentRunID) {
		return fmt.Errorf("event subject and scoped correlation do not match")
	}
	return nil
}

func validScopedID(value, reason string) bool {
	if value != "" {
		return reason == "" && opaqueIDPattern.MatchString(value)
	}
	switch reason {
	case "NOT_APPLICABLE", "NOT_CREATED", "UNAVAILABLE", "REDACTED_BY_POLICY":
		return true
	default:
		return false
	}
}

func validTraceContext(traceparent, tracestate string) bool {
	if !traceparentPattern.MatchString(traceparent) || strings.HasPrefix(traceparent, "ff-") || len(tracestate) > 512 || strings.ContainsAny(tracestate, "\r\n") {
		return false
	}
	parts := strings.Split(traceparent, "-")
	return len(parts) == 4 && parts[1] != strings.Repeat("0", 32) && parts[2] != strings.Repeat("0", 16)
}
