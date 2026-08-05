package artifact

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRetentionWorkerNotRunning = errors.New("artifact retention worker is not running")

type ExpiredPurger interface {
	PurgeExpired(context.Context, int) (RetentionReport, error)
}

type RetentionWorkerConfig struct {
	BatchSize      int
	PollInterval   time.Duration
	FailureBackoff time.Duration
}

type RetentionWorker struct {
	purger         ExpiredPurger
	batchSize      int
	pollInterval   time.Duration
	failureBackoff time.Duration
	running        atomic.Bool
	statusMu       sync.RWMutex
	lastError      error
}

func NewRetentionWorker(purger ExpiredPurger, config RetentionWorkerConfig) (*RetentionWorker, error) {
	if purger == nil || config.BatchSize < 0 || config.PollInterval < 0 || config.FailureBackoff < 0 {
		return nil, ErrInvalidRequest
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaultPurgeLimit
	}
	if config.BatchSize > maxPurgeLimit {
		return nil, ErrInvalidRequest
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Hour
	}
	if config.FailureBackoff == 0 {
		config.FailureBackoff = time.Minute
	}
	return &RetentionWorker{
		purger: purger, batchSize: config.BatchSize,
		pollInterval: config.PollInterval, failureBackoff: config.FailureBackoff,
	}, nil
}

func (worker *RetentionWorker) RunOnce(ctx context.Context) (RetentionReport, error) {
	if worker == nil || worker.purger == nil || ctx == nil {
		return RetentionReport{}, ErrInvalidRequest
	}
	return worker.purger.PurgeExpired(ctx, worker.batchSize)
}

func (worker *RetentionWorker) Run(ctx context.Context) error {
	if worker == nil || ctx == nil || !worker.running.CompareAndSwap(false, true) {
		return ErrInvalidRequest
	}
	defer worker.running.Store(false)
	for {
		report, err := worker.RunOnce(ctx)
		worker.statusMu.Lock()
		worker.lastError = err
		worker.statusMu.Unlock()
		wait := worker.pollInterval
		if err != nil {
			wait = worker.failureBackoff
		} else if report.Records == int64(worker.batchSize) {
			wait = 0
		}
		if wait == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (worker *RetentionWorker) Ready() error {
	if worker == nil || !worker.running.Load() {
		return ErrRetentionWorkerNotRunning
	}
	worker.statusMu.RLock()
	defer worker.statusMu.RUnlock()
	return worker.lastError
}
