# WP-01 Threat Model

## Assets

Protocol meaning, version negotiation, identity binding, state versions, content digests, error confidentiality, and compatibility behavior.

## Threats And Controls

| Threat | Control |
|---|---|
| Unknown intent interpreted as known work | closed intent enumeration and explicit incompatible-version error |
| Required security capability ignored | required-extension validation and negotiation failure |
| Spec or evidence substitution | canonical digest and exact version binding |
| Replay or stale command | message ID, idempotency key, expected version, nonce/lease context, expiry |
| Error-based tenant or secret leak | allowlisted public details and redacted Problem Details |
| Schema ambiguity | strict domain objects, conditional intent guards, semantic validation |
| Downgrade | fixed production versions and explicit experimental capability |
| Oversized protocol payload | bounded arrays, strings, and artifact references at ingress |

Wire validation is not authorization. Valid messages still require Orchestrator, policy, Lease, and current-state checks.
