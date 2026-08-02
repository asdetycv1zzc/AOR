# ADR-0002: Event Store, Projection, And Transactional Outbox

## Context
State, immutable audit events, and publication must survive crashes without lost or duplicated permanent effects.

## Decision
Store aggregate events, the current projection, idempotency result, and outbox row in one PostgreSQL transaction. Aggregate versions increase monotonically. Consumers deduplicate event IDs and rebuild projections from events.

## Alternatives
Direct event-bus publication risks the database-to-bus gap. Full event sourcing without query projections makes operational queries expensive.

## Security Consequences
Only the Orchestrator database role appends business events. Corrections are compensating events, never mutation.

## Operational Consequences
Outbox lag and projection drift require metrics, replay tooling, and reconciliation.

## Migration
Schemas follow expand-migrate-contract. Every projection version includes a replay fixture before deployment.

## Status
Accepted
