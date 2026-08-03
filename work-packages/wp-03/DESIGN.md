# WP-03 Design

## Trust boundaries

Authentication adapters are the boundary between untrusted bearer/SVID material and a normalized `authn.Principal`. They do not parse or persist private keys. Authorization is a second boundary: every request is normalized into a typed `PolicyInput`, checked for complete scope, then evaluated by a versioned local policy bundle. Capability leases are signed, short-lived proof objects and are revalidated at the point of side effect.

## Authentication

`OIDCAuthenticator` delegates signature/JWKS work to an injected verifier and validates issuer, exact audience, subject, time claims, principal type, role, and optional revocation. `SPIFFEAuthenticator` validates the canonical `spiffe://<trust-domain>/aor/<environment>/<service>/<instance>` shape and delegates SVID proof verification. Both authenticators use an injected clock and bounded skew so tests and production time policy are explicit.

## Authorization

`authz.Engine` performs structural validation before policy rules. The default rule set is deny-by-default and recognizes only documented action families. Executor repository writes must target a task-owned path; knowledge writes require a curator role and verified approval record; policy and production actions require break-glass approval with two distinct approvers. Side effects require a current lease whose fields exactly match the request. Custom rules can narrow the default behavior but cannot turn malformed or default-denied input into an allow.

## Lease lifecycle

`LeaseManager` stores immutable-by-copy lease records in a thread-safe `MemoryLeaseStore` for deterministic tests. `EvaluateLeaseGrant` creates an allow decision bound to the exact principal, tenant, project/task versions, spec and parameter digests, action, resource, and budget account. Issuance and renewal require that bound grant. Renewal increments fencing and replaces the signed record. Heartbeats update liveness without extending expiry. Revoke changes state and signs the tombstone. Validation verifies the signature, active state, expiry, heartbeat window, exact binding, and current fencing token.

## Cryptography and canonicalization

The default signer is HMAC-SHA256 over a fixed-order JSON payload containing all security-relevant lease fields except the signature. Keys are supplied by the caller and never serialized. A production deployment may provide an equivalent KMS-backed `Signer`; tests use a random key generated in memory.

## Failure behavior

Errors use the stable `pkg/errors` codes. Authentication failures use `AOR_UNAUTHORIZED` or `AOR_INVALID_ARGUMENT`; policy denials use `AOR_POLICY_DENIED`; expired leases use `AOR_LEASE_EXPIRED`; unavailable policy state uses `AOR_DEPENDENCY_UNAVAILABLE`. A denial decision is returned with a safe reason code even when a dependency error is also returned. No fallback role, cached allow, or inferred project scope is used for a write.
