package eventing

import (
	"context"
	"fmt"
)

// ReplayPending consumes the messages present when a fresh durable consumer is
// inspected. The caller must open the consumer from the beginning with a new
// durable name so the resulting batch represents a complete stream replay.
func (c *DurableConsumer) ReplayPending(ctx context.Context, handler func(context.Context, JetStreamDelivery) error) (uint64, error) {
	if c == nil || c.consumer == nil || ctx == nil || handler == nil {
		return 0, fmt.Errorf("%w: replay consumer and handler are required", ErrJetStreamEnvelope)
	}
	if _, found := ctx.Deadline(); !found {
		return 0, fmt.Errorf("%w: replay context requires a deadline", ErrJetStreamEnvelope)
	}
	info, err := c.consumer.Info(ctx)
	if err != nil {
		return 0, fmt.Errorf("inspect durable replay consumer: %w", err)
	}
	if info == nil || info.Delivered.Consumer != 0 || info.AckFloor.Consumer != 0 || info.NumAckPending != 0 {
		return 0, fmt.Errorf("%w: replay requires a fresh durable consumer", ErrJetStreamEnvelope)
	}
	pending := info.NumPending
	for processed := uint64(0); processed < pending; processed++ {
		delivery, err := c.Next(ctx)
		if err != nil {
			return processed, fmt.Errorf("read durable replay message: %w", err)
		}
		if err := handler(ctx, delivery); err != nil {
			_ = delivery.Nak()
			return processed, err
		}
		if err := delivery.Ack(); err != nil {
			return processed, fmt.Errorf("acknowledge durable replay message: %w", err)
		}
	}
	return pending, nil
}
