# Secret Exposure

Severity: SEV-1. Alert: `AORSecretExposure` or a credential fingerprint finding.

Symptoms: secret-shaped material appears in a prompt, workspace, log, trace, artifact, or error. Containment: revoke the lease and credential, quarantine affected artifacts, block provider calls, and preserve redacted evidence.

Diagnosis: search by the stable secret fingerprint across metadata and telemetry; inspect access logs and the exact boundary where the value was introduced. Never copy the value into the incident record.

Recovery: rotate the credential through the secret manager, invalidate cached responses and affected workspaces, and redeploy the gateway with the new reference.

Verification: run the secret corpus and boundary tests, confirm prompts and sandbox environments contain no provider key, and verify logs contain only the fingerprint and event metadata.

Evidence: retain fingerprints, timestamps, affected resource IDs, revocation receipts, and signed approvals. Retrospective: identify the leak path and add a permanent regression test.
