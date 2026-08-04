# Disaster Recovery

Severity: SEV-1. Alert: regional outage or declared disaster.

Symptoms: the primary region cannot serve control traffic or durable storage. Containment: declare the incident, fence the failed region, and route traffic only to the approved recovery target.

Diagnosis: record backup age, WAL position, object-store replication, secret and policy backup versions, and the last signed release digest.

Recovery: restore PostgreSQL with PITR, immutable artifacts, knowledge revisions, policy bundles, and signing roots. Apply migrations forward, replay the outbox, rebuild projections, and run the restore verifier before opening traffic.

Verification: record RPO/RTO, compare event and projection digests, exercise idempotent retries, and verify tenant isolation and lease fencing.

Evidence: preserve the recovery timeline, backup IDs, verifier and conformance reports, approvals, and traces. Retrospective: complete the regional drill report and corrective actions.
