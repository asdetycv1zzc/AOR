# Artifact Integrity Failure

Severity: SEV-1. Alert: `AORArtifactHashMismatch`.

Symptoms: an object hash differs from its immutable manifest or a referenced object is missing. Containment: stop publication and restore of the affected project, quarantine the object, and keep database references unchanged.

Diagnosis: compare manifest digest, object digest, size, tenant/project scope, version, and audit signatures. Inspect object-store version history and publication logs.

Recovery: restore the exact immutable object version from backup or mark the artifact unavailable through the controlled state machine. Never overwrite an existing content-addressed object.

Verification: run catalog integrity and backup restore verification, rebuild projections, and confirm no dangling reference remains.

Evidence: save both digests, object version IDs, manifests, traces, operator approvals, and the signed verifier result. Retrospective: document storage and detection controls.
