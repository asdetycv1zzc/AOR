// Package asyncapi exposes the stable v1 event view consumed by older AOR
// event handlers. New optional CloudEvents and data fields are intentionally
// not materialized, so they cannot alter v1 consumer behavior.
package asyncapi

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/akimisaka/aor/pkg/cloudevents"
)

type ProjectEventV1 struct {
	ID               string
	Source           string
	Type             string
	Subject          string
	Time             time.Time
	Traceparent      string
	ProjectID        string
	AggregateVersion int64
}

func DecodeProjectEventV1(payload []byte) (ProjectEventV1, error) {
	var event cloudevents.Event
	if err := json.Unmarshal(payload, &event); err != nil {
		return ProjectEventV1{}, err
	}
	if err := event.Validate(); err != nil {
		return ProjectEventV1{}, err
	}
	var data struct {
		ProjectID        string `json:"projectId"`
		AggregateVersion int64  `json:"aggregateVersion"`
	}
	if err := json.Unmarshal(event.Data, &data); err != nil || data.ProjectID == "" || data.AggregateVersion < 1 {
		return ProjectEventV1{}, fmt.Errorf("invalid AOR v1 project event data")
	}
	return ProjectEventV1{ID: event.ID, Source: event.Source, Type: event.Type, Subject: event.Subject, Time: event.Time, Traceparent: event.Traceparent, ProjectID: data.ProjectID, AggregateVersion: data.AggregateVersion}, nil
}
