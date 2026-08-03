# WP-03 Identity Policy Module Specification

- Task ID: `WP-03`
- Phase: `2`
- Goal baseline: `SPEC.md` version `2.0.0`
- Dependencies: `WP-01`, `WP-02` interfaces only
- Risk: `CRITICAL`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Provide deterministic authentication, authorization, workload identity, and short-lived capability leases. The package is a control-plane security boundary: missing, stale, malformed, or unavailable security facts are rejected rather than inferred.

## Responsibilities

- Normalize and validate user OIDC claims and SPIFFE-compatible workload identities.
- Model principals, trust domains, audiences, revocation, clock-skew, and short-lived credential checks.
- Evaluate structured policy inputs and return `ALLOW`, `DENY`, or `APPROVAL_REQUIRED` decisions with policy version, constraints, and reason codes.
- Issue, renew, heartbeat, validate, fence, and revoke signed capability leases bound to principal, tenant/project/task, action, resource, parameter digest, policy version, and budget account.
- Enforce commit-time checks for lease state, expiry, fencing token, identity binding, ownership paths, approvals, and project/task state.
- Publish policy artifacts and focused unit/security tests without exposing credentials or policy secrets.

## Non-responsibilities

- Persisting WP-02 aggregates or changing workflow transitions.
- Calling OPA over the network, a model provider, Tool Broker, Repository Service, or Sandbox Provider.
- Issuing provider API keys, signing production releases, or deciding business completion.
- Treating role labels or prompt content as a substitute for a verified principal and lease.

## Allowed paths

`internal/authn/`, `internal/authz/`, `policies/rego/`, `policies/data/`, `work-packages/wp-03/`.

## Forbidden paths

`SPEC.md`, `AGENTS.md`, `internal/state/`, `internal/workflow/`, `internal/eventing/`, `work-packages/wp-01/`, `work-packages/wp-02/`, provider credentials, signing keys, and production configuration.

## Data classification

Principal metadata, lease metadata, policy decisions, and reason codes are `INTERNAL`. Raw bearer tokens, SVID private material, HMAC keys, approval signatures, and secret values are never accepted into persisted structs or logs.

## Acceptance criteria

1. Invalid issuer, audience, SPIFFE trust domain, subject, not-before, expiry, revocation, or clock-window facts fail authentication.
2. Unknown or malformed policy input, unavailable policy bundles, missing leases, expired/revoked leases, stale fencing tokens, cross-tenant bindings, unowned paths, and invalid approvals fail closed.
3. All write/side-effect actions require an active, signed, capability lease; lease renewal revalidates policy and increments fencing.
4. Revocation is effective on the next authorization check and an old lease copy cannot pass after fencing changes.
5. Policy decisions contain stable decision values, policy version, constraints, and reason codes and never contain secret material.
6. `go test ./...`, `go vet ./...`, and `gofmt -l` checks pass.
