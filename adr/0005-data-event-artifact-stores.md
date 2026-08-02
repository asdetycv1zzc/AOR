# ADR-0005: PostgreSQL, NATS, And S3-Compatible Storage

## Context
AOR needs transactional metadata, durable event delivery, and immutable large artifacts in local and HA profiles.

## Decision
Use PostgreSQL for metadata/events/outbox, NATS JetStream for CloudEvents delivery, and S3-compatible content-addressed object storage. Local development may use a file artifact adapter.

## Alternatives
Kafka is viable but heavier for the initial profile. Database blobs impair streaming and retention. NATS KV is not the system of record.

## Security Consequences
Tenant/project identity is included in every authorization and storage key. Services use separate least-privilege credentials and TLS.

## Operational Consequences
All three stores require backup, capacity, integrity, lag, and failover monitoring.

## Migration
Adapters preserve event and artifact contracts. Migration verifies hashes before atomically changing references.

## Status
Accepted
