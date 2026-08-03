// Package workflow contains pure replay logic. All side effects are Activity responsibilities.
package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const CurrentVersion = 2

var (
	ErrUnsupportedVersion = errors.New("unsupported workflow history version")
	ErrIncompatibleWorker = errors.New("worker is incompatible with workflow history")
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	eventTypePattern      = regexp.MustCompile(`^io[.]aor[.][a-z][a-z0-9-]*[.][a-z][a-z0-9-]*[.]v[1-9][0-9]*$`)
	changeIDPattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	buildIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type Step struct {
	AggregateVersion int64  `json:"aggregateVersion"`
	EventType        string `json:"eventType"`
	EventSHA256      string `json:"eventSha256"`
}

type History struct {
	WorkflowVersion int             `json:"workflowVersion"`
	VersionMarkers  []VersionMarker `json:"versionMarkers,omitempty"`
	Steps           []Step          `json:"steps"`
}

type VersionMarker struct {
	ChangeID string `json:"changeId"`
	Version  int    `json:"version"`
}

type WorkerCompatibility struct {
	BuildID    string
	MinVersion int
	MaxVersion int
}

type ReplaySnapshot struct {
	LastAggregateVersion int64
	WorkflowVersion      int
	StateSHA256          string
	HistorySHA256        string
}

func Replay(history History) (ReplaySnapshot, error) {
	return ReplayWithWorker(history, WorkerCompatibility{BuildID: "aor-current", MinVersion: 1, MaxVersion: CurrentVersion})
}

func ReplayWithWorker(history History, worker WorkerCompatibility) (ReplaySnapshot, error) {
	history = cloneHistory(history)
	if history.WorkflowVersion == 0 {
		history.WorkflowVersion = 1
	}
	if !buildIDPattern.MatchString(worker.BuildID) || worker.MinVersion < 1 || worker.MaxVersion < worker.MinVersion || worker.MaxVersion > CurrentVersion {
		return ReplaySnapshot{}, ErrIncompatibleWorker
	}
	if history.WorkflowVersion < worker.MinVersion || history.WorkflowVersion > worker.MaxVersion {
		return ReplaySnapshot{}, ErrIncompatibleWorker
	}
	if err := validateHistory(history); err != nil {
		return ReplaySnapshot{}, err
	}
	encoded, err := json.Marshal(history)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	steps, err := json.Marshal(history.Steps)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	stateDigest, err := canonicaljson.Digest(steps)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	return ReplaySnapshot{LastAggregateVersion: int64(len(history.Steps)), WorkflowVersion: history.WorkflowVersion, StateSHA256: stateDigest, HistorySHA256: digest}, nil
}

func Upgrade(history History, targetVersion int) (History, error) {
	history = cloneHistory(history)
	if history.WorkflowVersion == 0 {
		history.WorkflowVersion = 1
	}
	if targetVersion < history.WorkflowVersion || targetVersion > CurrentVersion {
		return History{}, ErrUnsupportedVersion
	}
	if err := validateHistory(history); err != nil {
		return History{}, err
	}
	for history.WorkflowVersion < targetVersion {
		switch history.WorkflowVersion {
		case 1:
			history.WorkflowVersion = 2
			history.VersionMarkers = []VersionMarker{{ChangeID: "history-schema", Version: 2}}
		default:
			return History{}, ErrUnsupportedVersion
		}
		if err := validateHistory(history); err != nil {
			return History{}, err
		}
	}
	return cloneHistory(history), nil
}

func validateHistory(history History) error {
	if history.WorkflowVersion < 1 || history.WorkflowVersion > CurrentVersion {
		return ErrUnsupportedVersion
	}
	if history.WorkflowVersion == 1 && len(history.VersionMarkers) != 0 {
		return fmt.Errorf("version 1 history contains version markers")
	}
	if history.WorkflowVersion == 2 {
		if len(history.VersionMarkers) == 0 || !hasMarker(history.VersionMarkers, "history-schema", 2) {
			return fmt.Errorf("version 2 history is missing its schema marker")
		}
	}
	previous := ""
	for _, marker := range history.VersionMarkers {
		if !changeIDPattern.MatchString(marker.ChangeID) || marker.Version < 1 || marker.Version > CurrentVersion || marker.ChangeID <= previous {
			return fmt.Errorf("invalid workflow version marker")
		}
		previous = marker.ChangeID
	}
	for index, step := range history.Steps {
		if step.AggregateVersion != int64(index+1) || !eventTypePattern.MatchString(step.EventType) || !digestPattern.MatchString(step.EventSHA256) {
			return fmt.Errorf("invalid workflow step at index %d", index)
		}
	}
	return nil
}

func hasMarker(markers []VersionMarker, changeID string, version int) bool {
	index := sort.Search(len(markers), func(index int) bool { return markers[index].ChangeID >= changeID })
	return index < len(markers) && markers[index].ChangeID == changeID && markers[index].Version == version
}

func cloneHistory(history History) History {
	history.Steps = append([]Step(nil), history.Steps...)
	history.VersionMarkers = append([]VersionMarker(nil), history.VersionMarkers...)
	return history
}
