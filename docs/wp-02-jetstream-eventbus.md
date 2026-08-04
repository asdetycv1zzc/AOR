# WP-02 JetStream Event Bus

`internal/eventing.JetStreamEventBus` is the durable EventBus implementation
for the runtime's existing NATS JetStream client. It publishes the validated
AOR CloudEvents JSON envelope on this tenant-scoped subject form:

```
aor.events.<tenant-id>.<aggregate-type>
```

The adapter sets `Nats-Msg-Id` to the immutable domain `EventID`, so a retry
uses the same broker de-duplication key. It also carries tenant identity and
W3C `traceparent` / `tracestate` in headers, then checks those headers against
the CloudEvent envelope before a received delivery is exposed.

`OpenDurableConsumer` creates a pull consumer with `AckExplicitPolicy`.
Call `Ack` only after the side effect is committed; call `Nak` to request
redelivery, and `InProgress` while work legitimately exceeds `AckWait`.
Consumers can start at the stream beginning, new messages, a sequence, or a
time, and can replay instantly or at original pacing.

JetStream preserves the acknowledgement position of an existing durable. A
new durable name is required for a new replay start. Delivery is at-least-once:
publish retries, redelivery after an unacknowledged message, and consumer
restart can all produce duplicate deliveries. Consumers must retain their own
idempotency boundary; this adapter does not claim exactly-once processing.
