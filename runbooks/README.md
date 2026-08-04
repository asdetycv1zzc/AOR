# Operations Runbooks

Every runbook records symptoms, severity, alerts, immediate containment, diagnosis, recovery, verification, evidence preservation, and retrospective requirements. Exercise records are external signed evidence.

Required runbooks:

- `control-plane-outage.md`
- `database-failover.md`
- `workflow-stuck.md`
- `event-bus-backlog.md`
- `model-provider-outage.md`
- `budget-reconciliation.md`
- `sandbox-escape-suspected.md`
- `secret-exposure.md`
- `artifact-integrity-failure.md`
- `knowledge-corruption.md`
- `third-attempt-user-escalation.md`
- `agent-runaway-cost.md`
- `key-rotation.md`
- `disaster-recovery.md`
- `rollback-release.md`

An exercise record must include `runbook`, `environment`, `startedAt`, `endedAt`, `alert`, `operator`, `result`, `evidenceUris`, and `artifactSha256`. Production acceptance requires a signed record for every runbook from the previous 180 days; the repository cannot manufacture that operational evidence.
