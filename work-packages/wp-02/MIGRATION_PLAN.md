# WP-02 Migration Plan

The initial PostgreSQL migration creates tenant-scoped append-only events, projections, command results, outbox/inbox, approvals, specs, tasks, dependencies, attempt series, submissions, audit subjects, and user decisions.

Future changes use expand-migrate-contract. New columns are nullable or defaulted during mixed-version operation, backfilled with bounded jobs, and constrained only after all readers support them. Immutable event payloads are never rewritten; a new event version and projector handles semantic evolution.

Workflow changes use explicit version markers and replay fixtures. Rollback uses forward repair for committed immutable events rather than deleting history.
