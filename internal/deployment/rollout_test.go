package deployment

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRolloutAppliesCandidateBeforeCommitAndRecordsDigests(t *testing.T) {
	stable := Revision{ID: "stable", Digest: digest(1)}
	candidate := Revision{ID: "candidate", Digest: digest(2)}
	var applied []Revision
	manager, err := NewOperationalRolloutManager(
		stable,
		time.Minute,
		time.Now,
		func(revision Revision) error {
			applied = append(applied, revision)
			return nil
		},
		func(Revision) error { return nil },
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(candidate); err != nil {
		t.Fatal(err)
	}
	if active := manager.Active(); active != candidate {
		t.Fatalf("candidate was not applied during observation: %#v", active)
	}
	if len(applied) != 1 || applied[0] != candidate {
		t.Fatalf("unexpected applied revisions: %#v", applied)
	}
	history := manager.History()
	if len(history) != 1 || history[0].State != RolloutStarted || history[0].OldDigest != stable.Digest || history[0].NewDigest != candidate.Digest {
		t.Fatalf("unexpected rollout history: %#v", history)
	}
	history[0].NewDigest = digest(3)
	if manager.History()[0].NewDigest != candidate.Digest {
		t.Fatal("caller's history mutation changed append-only rollout history")
	}
	if err := manager.Commit(candidate.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRolloutAutomaticallyRestoresOnDeadline(t *testing.T) {
	stable := Revision{ID: "stable", Digest: digest(1)}
	candidate := Revision{ID: "candidate", Digest: digest(2)}
	applied := make(chan Revision, 2)
	manager, err := NewOperationalRolloutManager(
		stable,
		40*time.Millisecond,
		time.Now,
		func(revision Revision) error {
			applied <- revision
			return nil
		},
		func(Revision) error { return nil },
		10*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(candidate); err != nil {
		t.Fatal(err)
	}
	assertApplied(t, applied, candidate)
	assertApplied(t, applied, stable)
	if active := manager.Active(); active != stable {
		t.Fatalf("deadline did not restore stable revision: %#v", active)
	}
	history := manager.History()
	if len(history) != 2 || history[1].State != RolloutRolledBack || history[1].Reason != ErrRolloutExpired.Error() || history[1].OldDigest != candidate.Digest || history[1].NewDigest != stable.Digest {
		t.Fatalf("unexpected deadline history: %#v", history)
	}
}

func TestRolloutAutomaticallyRestoresOnHealthFailure(t *testing.T) {
	stable := Revision{ID: "stable", Digest: digest(1)}
	candidate := Revision{ID: "candidate", Digest: digest(2)}
	applied := make(chan Revision, 2)
	manager, err := NewOperationalRolloutManager(
		stable,
		time.Second,
		time.Now,
		func(revision Revision) error {
			applied <- revision
			return nil
		},
		func(Revision) error { return ErrRolloutUnhealthy },
		10*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(candidate); err != nil {
		t.Fatal(err)
	}
	assertApplied(t, applied, candidate)
	assertApplied(t, applied, stable)
	if active := manager.Active(); active != stable {
		t.Fatalf("health failure did not restore stable revision: %#v", active)
	}
	history := manager.History()
	if len(history) != 2 || history[1].Reason != ErrRolloutUnhealthy.Error() {
		t.Fatalf("unexpected health failure history: %#v", history)
	}
}

func TestRolloutCommitAndExplicitRollbackApplyOnlyConfiguration(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	stable := Revision{ID: "stable", Digest: digest(1)}
	candidate := Revision{ID: "candidate", Digest: digest(2)}
	var mu sync.Mutex
	var applied []Revision
	manager, err := NewOperationalRolloutManager(
		stable,
		time.Minute,
		func() time.Time { return now },
		func(revision Revision) error {
			mu.Lock()
			defer mu.Unlock()
			applied = append(applied, revision)
			return nil
		},
		func(Revision) error { return nil },
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(candidate); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(Revision{ID: "other", Digest: digest(3)}); !errors.Is(err, ErrRolloutBusy) {
		t.Fatalf("second rollout result = %v", err)
	}
	if err := manager.Commit(candidate.ID); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(candidate.ID, "operator rollback"); err != nil {
		t.Fatal(err)
	}
	if active := manager.Active(); active != stable {
		t.Fatalf("rollback did not restore stable revision: %#v", active)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(applied) != 2 || applied[0] != candidate || applied[1] != stable {
		t.Fatalf("rollout touched something other than its configuration revisions: %#v", applied)
	}
	history := manager.History()
	if len(history) != 3 || history[1].State != RolloutCommitted || history[2].State != RolloutRolledBack || history[2].OldDigest != candidate.Digest || history[2].NewDigest != stable.Digest {
		t.Fatalf("unexpected commit/rollback history: %#v", history)
	}
}

func TestOperationalRolloutRejectsUnboundedOrUnobservableRuntime(t *testing.T) {
	stable := Revision{ID: "stable", Digest: digest(1)}
	apply := func(Revision) error { return nil }
	health := func(Revision) error { return nil }
	for _, test := range []struct {
		timeout  time.Duration
		apply    ConfigurationApplier
		health   ConfigurationHealthCheck
		interval time.Duration
	}{
		{timeout: 16 * time.Minute, apply: apply, health: health, interval: time.Second},
		{timeout: time.Minute, health: health, interval: time.Second},
		{timeout: time.Minute, apply: apply, interval: time.Second},
		{timeout: time.Minute, apply: apply, health: health},
		{timeout: time.Minute, apply: apply, health: health, interval: 2 * time.Minute},
	} {
		if _, err := NewOperationalRolloutManager(stable, test.timeout, time.Now, test.apply, test.health, test.interval); !errors.Is(err, ErrRolloutInvalid) {
			t.Fatalf("unsafe operational rollout accepted: %#v", test)
		}
	}
}

func assertApplied(t *testing.T, applied <-chan Revision, expected Revision) {
	t.Helper()
	select {
	case revision := <-applied:
		if revision != expected {
			t.Fatalf("applied revision = %#v, want %#v", revision, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for revision %#v", expected)
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
