# WP-02 Interfaces

## Reducer

`state.Decide(aggregate, command) -> event, result, error`

Inputs contain normalized principal scope, command body, expected version, current server time supplied by the trusted caller, and verified external guard facts. Reducers never fetch guard facts themselves.

## Transaction Store

`Store.Execute(ctx, TransactionRequest) -> TransactionResult`

The request binds tenant, aggregate type/id, expected version, principal/idempotency key, request digest, event, next projection, result digest, and outbox payload. The store returns the first result for an identical duplicate and `AOR_IDEMPOTENCY_CONFLICT` for a different request digest.

## Inbox

`Inbox.Process(ctx, tenant, consumer, message, requestDigest, handler) -> result, error`

The PostgreSQL inbox durably claims a message before invoking its handler and stores a successful JSON result afterwards. This boundary deduplicates completed deliveries and preserves a failed message digest for retry, but it is not an external side-effect transaction: a crash after a handler side effect and before completion can invoke that handler again. Handlers that call external systems must use their own stable idempotency key.

## Projection

`Projector.Apply(event) -> applied events, current projection, error`

Events are immutable and carry aggregate ID/version, event ID/type, payload digest, timestamp, causation, correlation, tenant, and project.

## Workflow

The deterministic simulator accepts commands and emits activity requests. Side effects remain separate Activity interfaces.
