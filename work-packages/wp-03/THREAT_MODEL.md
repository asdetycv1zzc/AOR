# WP-03 Threat Model

## Assets

Principal authenticity, tenant/project/task scope, policy bundle version, capability leases, approval bindings, fencing tokens, and the confidentiality of credentials and signing keys.

## Threats and controls

| Threat | Control |
|---|---|
| Forged or replayed OIDC/SVID credential | Injected proof verifier, exact issuer/audience/trust-domain checks, expiry/not-before and revocation checks |
| Role spoofing or missing scope | Strict principal and policy-input validation; no default principal or role |
| Cross-tenant/project/task access | Exact tenant and project/task binding in policy input and lease |
| Lease replay after expiry/revoke/renewal | Signature, expiry, heartbeat deadline, revocation state, and monotonic fencing token |
| Parameter or path substitution | Parameter digest binding and normalized path ownership/glob checks at commit time |
| Policy outage or malformed policy result | Bundle availability/version checks and fail-closed denial |
| Approval replay or privilege escalation | Subject/principal/expiry/revocation checks; high-risk action allowlist |
| Secret exposure through errors or decisions | Stable redacted errors, bounded safe reason codes, no credential fields in JSON |
| Concurrent renew/revoke race | Store compare-and-update under one lock; validation reads current record |

## Residual risk

The package cannot prove an injected verifier or external policy bundle is trustworthy; production must pin and attest those dependencies. HMAC is a local reference signer, not a replacement for a managed key service. In-memory leases are process-local and are for tests only.
