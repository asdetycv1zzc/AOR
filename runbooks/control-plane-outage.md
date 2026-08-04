# Control Plane Outage

Severity: SEV-1. Alert: `AORControlPlaneAvailability` or sustained API 5xx.

Symptoms: readiness fails, commands time out, or committed requests stop progressing. Containment: keep the public endpoint in maintenance mode, stop new deployments, and preserve the current release evidence and trace IDs. Do not delete workflow or database data.

Diagnosis: inspect `docker compose ps`, service readiness endpoints, database connectivity, Temporal health, NATS health, and recent logs with `docker compose logs --since=15m aor-api aor-worker temporal nats postgres`. Confirm whether the transactional outbox is growing.

Recovery: restore the failed stateless replica or roll back to the last signed release. Keep PostgreSQL and the event bus running while replacing application replicas. Drain the outbox after readiness returns.

Verification: run the health checks, submit one authenticated idempotent project read, verify one event cursor can resume, and confirm no duplicate command or outbox record was created.

Evidence: save timestamps, release digest, health output, trace IDs, outbox depth, operator identity, and the signed incident bundle. Retrospective: document cause, duration, lost requests (must be zero), and corrective actions within five business days.
