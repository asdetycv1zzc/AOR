# WP-03 Operations

## Signals

- Count authentication failures by issuer/trust domain and reason code, without logging tokens.
- Track `aor_agent_lease_issued_total`, `aor_agent_lease_expired_total`, `aor_agent_lease_revoked_total`, `aor_policy_decision_total{decision,policy_version,reason}`, and policy evaluation latency.
- Alert on policy bundle unavailable, signature/key errors, revocation spikes, fencing conflicts, and clock-skew rejection.

## Runbook

On policy or identity dependency failure, stop new side-effect leases, keep existing checks fail closed, and preserve correlation IDs and safe reason codes. Restore the pinned bundle/verifier, validate its digest and signature, then issue a new lease; do not revive an expired or revoked lease. On suspected key exposure, revoke affected leases, rotate the signer/verifier key, invalidate the bundle, and preserve an incident record without copying the secret.

## Configuration

Trust domains, issuers, audiences, clock skew, lease TTL, heartbeat interval, policy bundle digest, and maximum lease TTL are immutable security settings unless an audited reload is explicitly supported. Unknown configuration fields are errors. Provider/API secrets are references handled by the gateway or secret manager, never by this package.
