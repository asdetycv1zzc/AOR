package eventing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var ErrOutboxClaimLost = errors.New("outbox claim is no longer current")

type OutboxClaim struct {
	Record  OutboxRecord
	Attempt int
}

type OutboxStore interface {
	ClaimOutbox(ctx context.Context, tenantID string, now time.Time, limit int, lease time.Duration) ([]OutboxClaim, error)
	MarkOutboxPublished(ctx context.Context, tenantID, outboxID string, attempt int, publishedAt time.Time) error
	RetryOutbox(ctx context.Context, tenantID, outboxID string, attempt int, nextAttempt time.Time) error
}

type EventBus interface {
	Publish(ctx context.Context, event DomainEvent) error
}

type OutboxPublisherConfig struct {
	BatchSize      int
	Concurrency    int
	ClaimTTL       time.Duration
	PublishTimeout time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	PollInterval   time.Duration
	Clock          func() time.Time
}

type PublishBatchResult struct {
	Claimed   int
	Published int
	Retried   int
}

type publishOutcome struct {
	published bool
	retried   bool
	err       error
}

type OutboxPublisher struct {
	store          OutboxStore
	bus            EventBus
	batchSize      int
	concurrency    int
	claimTTL       time.Duration
	publishTimeout time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
	pollInterval   time.Duration
	clock          func() time.Time
}

func NewOutboxPublisher(store OutboxStore, bus EventBus, config OutboxPublisherConfig) (*OutboxPublisher, error) {
	if store == nil || bus == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox publisher dependency"})
	}
	if config.BatchSize < 0 || config.Concurrency < 0 || config.ClaimTTL < 0 || config.PublishTimeout < 0 || config.InitialBackoff < 0 || config.MaxBackoff < 0 || config.PollInterval < 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox publisher config"})
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.Concurrency == 0 {
		config.Concurrency = 8
	}
	if config.Concurrency > config.BatchSize {
		config.Concurrency = config.BatchSize
	}
	if config.ClaimTTL == 0 {
		config.ClaimTTL = 30 * time.Second
	}
	if config.PublishTimeout == 0 {
		config.PublishTimeout = config.ClaimTTL / 2
	}
	if config.InitialBackoff == 0 {
		config.InitialBackoff = time.Second
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = time.Minute
	}
	if config.PollInterval == 0 {
		config.PollInterval = 100 * time.Millisecond
	}
	if config.PublishTimeout > config.ClaimTTL || config.MaxBackoff < config.InitialBackoff {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox publisher timing"})
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &OutboxPublisher{
		store: store, bus: bus, batchSize: config.BatchSize, concurrency: config.Concurrency,
		claimTTL: config.ClaimTTL, publishTimeout: config.PublishTimeout, initialBackoff: config.InitialBackoff,
		maximumBackoff: config.MaxBackoff, pollInterval: config.PollInterval, clock: config.Clock,
	}, nil
}

func (p *OutboxPublisher) RunOnce(ctx context.Context, tenantID string) (PublishBatchResult, error) {
	if tenantID == "" {
		return PublishBatchResult{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox tenant"})
	}
	claims, err := p.store.ClaimOutbox(ctx, tenantID, p.clock().UTC(), p.batchSize, p.claimTTL)
	if err != nil {
		return PublishBatchResult{}, err
	}
	result := PublishBatchResult{Claimed: len(claims)}
	if len(claims) == 0 {
		return result, nil
	}

	jobs := make(chan OutboxClaim, len(claims))
	outcomes := make(chan publishOutcome, len(claims))
	for _, claim := range claims {
		jobs <- claim
	}
	close(jobs)

	workers := p.concurrency
	if workers > len(claims) {
		workers = len(claims)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for claim := range jobs {
				outcomes <- p.publishClaim(ctx, tenantID, claim)
			}
		}()
	}
	wait.Wait()
	close(outcomes)

	var batchErr error
	for item := range outcomes {
		if item.published {
			result.Published++
		}
		if item.retried {
			result.Retried++
		}
		if item.err != nil {
			batchErr = errors.Join(batchErr, item.err)
		}
	}
	return result, batchErr
}

func (p *OutboxPublisher) Run(ctx context.Context, tenantID string) error {
	for {
		result, err := p.RunOnce(ctx, tenantID)
		if err != nil {
			return err
		}
		if result.Claimed == p.batchSize {
			continue
		}
		timer := time.NewTimer(p.pollInterval)
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

func (p *OutboxPublisher) publishClaim(ctx context.Context, tenantID string, claim OutboxClaim) publishOutcome {
	publishCtx, cancel := context.WithTimeout(ctx, p.publishTimeout)
	err := p.bus.Publish(publishCtx, cloneEvent(claim.Record.Event))
	cancel()
	completedAt := p.clock().UTC()
	if err == nil {
		if markErr := p.store.MarkOutboxPublished(ctx, tenantID, claim.Record.ID, claim.Attempt, completedAt); markErr != nil {
			return publishOutcome{err: fmt.Errorf("mark outbox %s published: %w", claim.Record.ID, markErr)}
		}
		return publishOutcome{published: true}
	}
	nextAttempt := completedAt.Add(retryDelay(claim.Attempt, p.initialBackoff, p.maximumBackoff))
	if retryErr := p.store.RetryOutbox(ctx, tenantID, claim.Record.ID, claim.Attempt, nextAttempt); retryErr != nil {
		return publishOutcome{err: errors.Join(fmt.Errorf("publish outbox %s: %w", claim.Record.ID, err), fmt.Errorf("reschedule outbox %s: %w", claim.Record.ID, retryErr))}
	}
	return publishOutcome{retried: true}
}

func retryDelay(attempt int, initial, maximum time.Duration) time.Duration {
	delay := initial
	for current := 1; current < attempt && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
