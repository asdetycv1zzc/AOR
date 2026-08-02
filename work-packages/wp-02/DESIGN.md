# WP-02 Design

The state package is a pure deterministic reducer. A command plus current aggregate either returns a typed event/result or a stable AOR error; it performs no clock, network, file, model, or database access.

The Orchestrator loads an aggregate, validates the expected version and command digest, runs the reducer, and submits one transaction containing the new projection, immutable event, idempotency record, and outbox entry. Storage adapters implement the same compare-and-append contract. PostgreSQL is authoritative in deployed profiles; an in-memory adapter supports model and property tests.

Attempts are grouped by immutable `attemptSeriesId` bound to `moduleTaskId + moduleSpecVersion`. Attempt values are 1 through 3. Only an immutable user decision can create a new series. `DONE` is never persisted; it is computed from `INTEGRATED` plus section 38.1 evidence.

Projection consumers deduplicate `eventId`. Per aggregate, contiguous versions apply immediately, future versions buffer, prior versions are ignored only when their event ID and payload digest match history. Any conflicting duplicate fails closed.
