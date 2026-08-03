# WP-03 Interfaces

## Authentication

- `authn.Principal` is the normalized, safe-to-log identity.
- `authn.OIDCAuthenticator.Authenticate(ctx, Credential) (Principal, error)` validates claims from an injected `OIDCVerifier`.
- `authn.SPIFFEAuthenticator.Authenticate(ctx, Credential) (Principal, error)` validates a verified SVID from an injected `SVIDVerifier`.
- `authn.ParseSPIFFEID` and `authn.ValidateOIDCClaims` are pure validation helpers.

## Authorization

- `authz.Engine.Evaluate(ctx, PolicyInput) (PolicyDecision, error)` returns `ALLOW`, `DENY`, or `APPROVAL_REQUIRED`.
- `authz.Engine.Authorize` is an alias intended for side-effect call sites.
- `PolicyInput` contains principal, tenant/project, task, action, resource, lease reference, approval, and execution context. All fields are explicit; no ambient request state is read.
- `PolicyDecision` includes `Decision`, `PolicyVersion`, `Constraints`, `ReasonCodes`, and `RuleID`.

## Capability leases

- `authz.LeaseManager.Issue(ctx, LeaseRequest)`, `Renew(ctx, LeaseRenewalRequest)`, `Heartbeat(ctx, LeaseHeartbeatRequest)`, `Revoke(ctx, LeaseRevokeRequest)`, and `Validate(ctx, LeaseCheck)` implement the lease lifecycle.
- `authz.LeaseStore` is the persistence seam. `MemoryLeaseStore` is deterministic and concurrency safe; a database implementation can preserve the same compare-and-fence semantics.
- `CapabilityLease` is signed and includes principal, project/task, action/resource, parameter digest, policy version, budget account, nonce, expiry, heartbeat, and fencing token.

Times are UTC RFC3339 values at serialization boundaries. Inputs are never mutated. Callers must supply a trusted server time for security checks.
