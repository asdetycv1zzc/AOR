# Key Rotation

Severity: SEV-2, SEV-1 for suspected compromise. Alert: key expiry, signature failure, or rotation drill failure.

Symptoms: Agent Card, JWT, lease, or release signatures fail validation or approach expiry. Containment: keep the old verification key available for the documented overlap window, stop issuing new credentials if compromise is suspected, and record the approval.

Diagnosis: verify key IDs, validity windows, revocation state, issuer/audience, card signatures, and the active configuration digest. Never log private key material.

Recovery: publish the new public key, rotate the secret-manager reference, reload or restart services according to the catalog, and revoke the old key after the overlap window.

Verification: test new signatures, expired/revoked signatures, old-key rejection after revocation, and restart/replay behavior.

Evidence: retain key IDs, rotation timestamps, approvals, public certificates, and signed test results. Retrospective: record propagation and rollback readiness.
