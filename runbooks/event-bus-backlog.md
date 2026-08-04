# Event Bus Backlog

Severity: SEV-2. Alert: `AOROutboxBacklog`.

Symptoms: outbox age or pending count increases while database commits succeed. Containment: preserve the outbox, rate-limit new high-volume commands, and do not acknowledge messages that were not durably processed.

Diagnosis: inspect NATS JetStream health, consumer lag, outbox tenant counts, publisher errors, and duplicate inbox claims. Check network and credentials without printing secret values.

Recovery: restore the publisher or event bus, then drain with bounded concurrency. Reconcile projections from the immutable event log and retry only records whose lease is still valid.

Verification: confirm monotonic aggregate versions, no missing event IDs, stable inbox deduplication, and backlog age below the SLO for the configured window.

Evidence: save backlog samples, event and outbox digests, consumer state, traces, and the recovery release digest. Retrospective: record the interruption and capacity margin.
