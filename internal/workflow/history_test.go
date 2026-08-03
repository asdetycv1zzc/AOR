package workflow

import (
	"encoding/json"
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
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "workflow", "v1-history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var history History
	if err := json.Unmarshal(content, &history); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(history); err != nil {
		t.Fatal(err)
	}
}

func digestZero() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func digestOne() string {
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}
