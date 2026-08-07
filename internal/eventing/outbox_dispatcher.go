package eventing

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var ErrOutboxDispatcherNotRunning = errors.New("outbox dispatcher is not running")
var ErrOutboxPublishDeferred = errors.New("one or more outbox records were deferred for retry")

// OutboxTenantSource discovers tenant partitions with publishable records. The
// implementation must not rely on a request-scoped tenant setting because the
// dispatcher is responsible for recovering work after a process restart.
type OutboxTenantSource interface {
	PendingOutboxTenants(ctx context.Context, now time.Time, limit int) ([]string, error)
}

type OutboxDispatcherConfig struct {
	TenantBatchSize int
	PollInterval    time.Duration
	FailureBackoff  time.Duration
	Clock           func() time.Time
}

type DispatchResult struct {
	Tenants   int
	Claimed   int
	Published int
	Retried   int
}

// OutboxDispatcher continuously discovers tenant partitions and drains each
// partition through OutboxPublisher. Publish failures remain retryable and do
// not terminate the process loop.
type OutboxDispatcher struct {
	tenants        OutboxTenantSource
	publisher      *OutboxPublisher
	tenantBatch    int
	pollInterval   time.Duration
	failureBackoff time.Duration
	clock          func() time.Time
	running        atomic.Bool
}

func NewOutboxDispatcher(tenants OutboxTenantSource, publisher *OutboxPublisher, config OutboxDispatcherConfig) (*OutboxDispatcher, error) {
	if tenants == nil || publisher == nil || config.TenantBatchSize < 0 || config.PollInterval < 0 || config.FailureBackoff < 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox dispatcher configuration"})
	}
	if config.TenantBatchSize == 0 {
		config.TenantBatchSize = 100
	}
	if config.TenantBatchSize > 1000 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox dispatcher tenant batch"})
	}
	if config.PollInterval == 0 {
		config.PollInterval = 100 * time.Millisecond
	}
	if config.FailureBackoff == 0 {
		config.FailureBackoff = time.Second
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &OutboxDispatcher{
		tenants: tenants, publisher: publisher, tenantBatch: config.TenantBatchSize,
		pollInterval: config.PollInterval, failureBackoff: config.FailureBackoff, clock: config.Clock,
	}, nil
}

func (dispatcher *OutboxDispatcher) RunOnce(ctx context.Context) (DispatchResult, error) {
	if dispatcher == nil || dispatcher.tenants == nil || dispatcher.publisher == nil || ctx == nil {
		return DispatchResult{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox dispatch"})
	}
	tenantIDs, err := dispatcher.tenants.PendingOutboxTenants(ctx, dispatcher.clock().UTC(), dispatcher.tenantBatch)
	if err != nil {
		return DispatchResult{}, err
	}
	result := DispatchResult{Tenants: len(tenantIDs)}
	seen := make(map[string]struct{}, len(tenantIDs))
	var dispatchErr error
	for _, tenantID := range tenantIDs {
		if tenantID == "" {
			dispatchErr = errors.Join(dispatchErr, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "empty outbox tenant"}))
			continue
		}
		if _, duplicate := seen[tenantID]; duplicate {
			dispatchErr = errors.Join(dispatchErr, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "duplicate outbox tenant"}))
			continue
		}
		seen[tenantID] = struct{}{}
		batch, publishErr := dispatcher.publisher.RunOnce(ctx, tenantID)
		result.Claimed += batch.Claimed
		result.Published += batch.Published
		result.Retried += batch.Retried
		if publishErr != nil {
			dispatchErr = errors.Join(dispatchErr, publishErr)
		}
	}
	return result, dispatchErr
}

func (dispatcher *OutboxDispatcher) Run(ctx context.Context) error {
	if dispatcher == nil || ctx == nil || !dispatcher.running.CompareAndSwap(false, true) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox dispatcher run"})
	}
	defer dispatcher.running.Store(false)
	for {
		result, err := dispatcher.RunOnce(ctx)
		statusErr := err
		if statusErr == nil && result.Retried > 0 {
			statusErr = ErrOutboxPublishDeferred
		}
		wait := dispatcher.pollInterval
		if statusErr != nil {
			wait = dispatcher.failureBackoff
		} else if result.Tenants == dispatcher.tenantBatch || result.Claimed > 0 {
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

func (dispatcher *OutboxDispatcher) Ready() error {
	if dispatcher == nil || !dispatcher.running.Load() {
		return ErrOutboxDispatcherNotRunning
	}
	return nil
}
