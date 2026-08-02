# ADR-0008: OPA Policy And Capability Leases

## Context
Role labels alone cannot bind a tool action to the current project, task, parameters, time, version, and budget.

## Decision
OPA evaluates structured authorization context and returns deny, allow, or approval required with constraints. A signed, short-lived, nonce-bearing Capability Lease binds the approved principal, task, action, resource, parameter digest, and policy version.

## Alternatives
Prompt instructions are not access control. Static ACLs cannot express commit-time conditions.

## Security Consequences
Default is deny. Permanent effects revalidate identity, approval, state, versions, parameters, policy, and budget at commit time.

## Operational Consequences
Policy bundle distribution, decision latency, lease revocation, and clock behavior require monitoring.

## Migration
New bundles are versioned and signed. Critical forced migration emits an event and revokes affected leases.

## Status
Accepted
