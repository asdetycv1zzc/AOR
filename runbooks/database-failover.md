# Database Failover

Severity: SEV-1. Alert: `AORDatabaseReplicationFailure` or primary connection failure.

Symptoms: transaction errors, stale projections, or failed health checks. Containment: disable writes at the ingress gateway, retain the old primary for forensic capture, and prevent a second writer from starting.

Diagnosis: record replication position, leader lease, WAL/PITR status, active connections, and migration version. Use the deployment's read-only database health command and inspect `aor` service logs.

Recovery: promote the approved synchronous replica using the platform procedure, update the secret-backed endpoint, and restart only after fencing the old primary. Replay the transactional outbox and run the restore verifier before reopening writes.

Verification: prove the configured RPO/RTO, compare projection and event digests, run duplicate-command and lease-fencing checks, and verify migration compatibility.

Evidence: preserve replication metrics, promotion record, WAL positions, operator approvals, verifier report, and trace IDs. Retrospective: record split-brain prevention and follow-up capacity work.
