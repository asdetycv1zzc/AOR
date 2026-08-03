# WP-02 Changelog

## 0.1.0 - 2026-08-02

- Froze the state authority, transaction, replay, attempt-series, and migration design.

## 0.2.0 - 2026-08-03

- Implemented deterministic Project and ModuleTask reducers with expected-version and fencing guards.
- Added immutable approval bindings, transactional idempotency, outbox records, crash-window injection, tenant-scoped projections, and disorder-tolerant replay.
- Added PostgreSQL tenant composite references, forced row-level security, immutable-record triggers, and relational project projection synchronization.
- Added state-machine, integration, replay, and performance fixtures. PostgreSQL execution against a live server and signed Evidence Bundle remain release-gate work.
