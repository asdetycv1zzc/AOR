package workflow

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplayIsDeterministicAndRejectsVersionGaps(t *testing.T) {
	history := History{Steps: []Step{{AggregateVersion: 1, EventType: "io.aor.project.created.v1", EventSHA256: digestZero()}, {AggregateVersion: 2, EventType: "io.aor.goal.proposed.v1", EventSHA256: digestOne()}}}
	first, err := Replay(history)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Replay(history)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.LastAggregateVersion != 2 {
		t.Fatalf("replay mismatch: %#v != %#v", first, second)
	}
	history.Steps[1].AggregateVersion = 3
	if _, err := Replay(history); err == nil {
		t.Fatal("workflow history gap was accepted")
	}
}

func TestVersionOneFixtureReplays(t *testing.T) {
	history := readFixture(t, "v1-history.json")
	if _, err := Replay(history); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowUpgradePreservesLogicalReplayState(t *testing.T) {
	versionOne := readFixture(t, "v1-history.json")
	before, err := Replay(versionOne)
	if err != nil {
		t.Fatal(err)
	}
	versionTwo, err := Upgrade(versionOne, 2)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Upgrade(versionTwo, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !historiesEqual(versionTwo, again) {
		t.Fatalf("upgrade is not idempotent: %#v != %#v", versionTwo, again)
	}
	after, err := Replay(versionTwo)
	if err != nil {
		t.Fatal(err)
	}
	if before.StateSHA256 != after.StateSHA256 || before.LastAggregateVersion != after.LastAggregateVersion || after.WorkflowVersion != 2 || before.HistorySHA256 == after.HistorySHA256 {
		t.Fatalf("upgrade changed replay state: before=%#v after=%#v", before, after)
	}
}

func TestWorkerCompatibilityWindowFencesNewHistories(t *testing.T) {
	versionOne := readFixture(t, "v1-history.json")
	versionTwo := readFixture(t, "v2-history.json")
	oldWorker := WorkerCompatibility{BuildID: "worker-v1", MinVersion: 1, MaxVersion: 1}
	if _, err := ReplayWithWorker(versionOne, oldWorker); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayWithWorker(versionTwo, oldWorker); !errors.Is(err, ErrIncompatibleWorker) {
		t.Fatalf("old worker accepted v2 history: %v", err)
	}
	currentWorker := WorkerCompatibility{BuildID: "worker-v2", MinVersion: 1, MaxVersion: 2}
	if _, err := ReplayWithWorker(versionOne, currentWorker); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayWithWorker(versionTwo, currentWorker); err != nil {
		t.Fatal(err)
	}
	versionTwo.VersionMarkers = append(versionTwo.VersionMarkers, VersionMarker{ChangeID: "history-schema", Version: 2})
	if _, err := ReplayWithWorker(versionTwo, currentWorker); err == nil {
		t.Fatal("duplicate version marker was accepted")
	}
}

func readFixture(t *testing.T, name string) History {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "workflow", name))
	if err != nil {
		t.Fatal(err)
	}
	var history History
	if err := json.Unmarshal(content, &history); err != nil {
		t.Fatal(err)
	}
	return history
}

func historiesEqual(left, right History) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func digestZero() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func digestOne() string {
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}
