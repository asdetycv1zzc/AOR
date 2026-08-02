# ADR-0022: User Approval And Third-Attempt Decisions

## Context
Agent consensus cannot approve goals, risk, or attempts, and a third failed submission must not trigger autonomous retry.

## Decision
Persist immutable Approval Records bound to actor, action, exact version and digest, constraints, issue time, expiry, and revocation. On third failure, block the module, freeze dependents, and expose only the decision set in SPEC section 41.2. No decision may ignore audit and mark work complete.

## Alternatives
Natural-language consent without a digest is ambiguous. Automatic replanning bypasses the attempt invariant.

## Security Consequences
Permanent effects revalidate approval at commit time. Reset creates a new attempt series and preserves all history.

## Operational Consequences
CLI and API provide downloadable evidence, dependency impact, cost, and allowed decisions.

## Migration
Legacy decisions map to the closest non-bypassing canonical decision or require fresh user approval.

## Status
Accepted
