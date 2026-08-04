# Rollback Release

Severity: SEV-1 for safety regressions, SEV-2 otherwise. Alert: release health or canary SLO failure.

Symptoms: a signed canary violates a release gate, SLO, schema, or security invariant. Containment: stop promotion and keep immutable events and data writes available only through the current safe version.

Diagnosis: compare source, image, migration, configuration, SBOM, provenance, and release-evidence digests. Identify whether the change is code, configuration, or migration related.

Recovery: use the rollout manager to revert to the previous signed revision. For migrations, apply the documented forward-compatible repair; never reset or delete immutable history.

Verification: run health, schema, replay, migration, security, and smoke checks; verify the active revision and release evidence signature.

Evidence: retain canary metrics, gate output, rollback events, operator approvals, and traces. Retrospective: document why promotion passed and add a regression gate.
