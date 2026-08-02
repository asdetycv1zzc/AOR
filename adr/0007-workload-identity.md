# ADR-0007: SPIFFE And OIDC Identity

## Context
Humans and workloads need independently verifiable, short-lived identity without static service secrets.

## Decision
Use OIDC for users and SPIFFE-compatible workload identities for services and workers. Translate verified claims into a normalized principal and issue short-lived internal credentials.

## Alternatives
Long-lived API keys increase rotation and exfiltration risk. Network location is not identity.

## Security Consequences
Trust domains separate environments. Audience, issuer, expiry, revocation, and clock tolerance are checked on each sensitive operation.

## Operational Consequences
Identity issuance and rotation are critical dependencies with dedicated alerts and break-glass procedures.

## Migration
Adapters support approved issuers; dual trust is time-bounded and audited during issuer rotation.

## Status
Accepted
