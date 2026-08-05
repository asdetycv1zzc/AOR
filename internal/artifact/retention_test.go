package artifact

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type retentionPurger struct {
	mu      sync.Mutex
	calls   int
	reports []RetentionReport
	errors  []error
}

func (purger *retentionPurger) PurgeExpired(context.Context, int) (RetentionReport, error) {
	purger.mu.Lock()
	defer purger.mu.Unlock()
	index := purger.calls
	purger.calls++
	var report RetentionReport
	if index < len(purger.reports) {
		report = purger.reports[index]
	}
	if index < len(purger.errors) {
		return report, purger.errors[index]
	}
	return report, nil
}

func (purger *retentionPurger) callCount() int {
	purger.mu.Lock()
	defer purger.mu.Unlock()
	return purger.calls
}

func TestRetentionWorkerRetriesAndRecovers(t *testing.T) {
	transient := errors.New("temporary object store failure")
	purger := &retentionPurger{errors: []error{transient, nil}}
	worker, err := NewRetentionWorker(purger, RetentionWorkerConfig{
		BatchSize: 1, PollInterval: time.Millisecond, FailureBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for purger.callCount() < 2 {
		select {
		case <-deadline.C:
			cancel()
			t.Fatal("retention worker did not retry")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := worker.Ready(); err != nil {
		cancel()
		t.Fatalf("retention worker did not recover: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if !errors.Is(worker.Ready(), ErrRetentionWorkerNotRunning) {
		t.Fatalf("Ready after stop = %v", worker.Ready())
	}
}

func TestRetentionWorkerDrainsFullBatchesImmediately(t *testing.T) {
	purger := &retentionPurger{reports: []RetentionReport{{Records: 1}, {}}}
	worker, err := NewRetentionWorker(purger, RetentionWorkerConfig{
		BatchSize: 1, PollInterval: time.Hour, FailureBackoff: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for purger.callCount() < 2 {
		select {
		case <-deadline.C:
			cancel()
			t.Fatal("retention worker did not drain a full batch")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}
