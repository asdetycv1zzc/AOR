package deployment

import (
	"errors"
	"testing"
	"time"
)

func TestRolloutExpiresPendingRevisionAndKeepsActiveConfig(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	manager, err := NewRolloutManager(Revision{ID: "stable", Digest: digest(1)}, 15*time.Minute, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(Revision{ID: "candidate", Digest: digest(2)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(16 * time.Minute)
	if active := manager.Active(); active.ID != "stable" {
		t.Fatalf("expired candidate became active: %#v", active)
	}
	if _, _, pending := manager.Pending(); pending {
		t.Fatal("expired rollout remained pending")
	}
	history := manager.History()
	if len(history) != 2 || history[1].State != RolloutRolledBack || !errors.Is(ErrRolloutExpired, ErrRolloutExpired) {
		t.Fatalf("unexpected expiry history: %#v", history)
	}
}

func TestRolloutCommitAndExplicitRollbackAreBounded(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	manager, err := NewRolloutManager(Revision{ID: "stable", Digest: digest(1)}, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	candidate := Revision{ID: "candidate", Digest: digest(2)}
	if err := manager.Start(candidate); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(Revision{ID: "other", Digest: digest(3)}); !errors.Is(err, ErrRolloutBusy) {
		t.Fatalf("second rollout result = %v", err)
	}
	if err := manager.Commit(candidate.ID); err != nil {
		t.Fatal(err)
	}
	if active := manager.Active(); active.ID != candidate.ID {
		t.Fatalf("candidate was not committed: %#v", active)
	}
	if err := manager.Rollback(candidate.ID, "health check failed"); err != nil {
		t.Fatal(err)
	}
	if active := manager.Active(); active.ID != "stable" {
		t.Fatalf("rollback did not restore previous revision: %#v", active)
	}
}

func digest(value byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len("sha256:")+64)
	copy(result, "sha256:")
	for index := 0; index < 64; index++ {
		result[len("sha256:")+index] = hex[int(value)%len(hex)]
	}
	return string(result)
}
