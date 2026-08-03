// Package workflow contains pure replay logic. All side effects are Activity responsibilities.
package workflow

import (
	"encoding/json"
	"fmt"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type Step struct {
	AggregateVersion int64  `json:"aggregateVersion"`
	EventType        string `json:"eventType"`
	EventSHA256      string `json:"eventSha256"`
}

type History struct {
	WorkflowVersion int    `json:"workflowVersion"`
	Steps           []Step `json:"steps"`
}

type ReplaySnapshot struct {
	LastAggregateVersion int64
	HistorySHA256        string
}

func Replay(history History) (ReplaySnapshot, error) {
	if history.WorkflowVersion == 0 {
		history.WorkflowVersion = 1
	}
	if history.WorkflowVersion != 1 {
		return ReplaySnapshot{}, fmt.Errorf("unsupported workflow history version")
	}
	for index, step := range history.Steps {
		if step.AggregateVersion != int64(index+1) || step.EventType == "" || len(step.EventSHA256) != 71 {
			return ReplaySnapshot{}, fmt.Errorf("invalid workflow step at index %d", index)
		}
	}
	encoded, err := json.Marshal(history)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	return ReplaySnapshot{LastAggregateVersion: int64(len(history.Steps)), HistorySHA256: digest}, nil
}
