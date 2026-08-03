# WP-08 Threat Model

| Threat | Control |
|---|---|
| Agent self-approval | Only a user-bound Approval Record can move the project to Planning |
| Challenger collusion | Distinct agent identity and immutable challenge artifact |
| Mutable or substituted spec | Canonical content hash, exact version reference and immutable artifact key |
| Cyclic or dangling DAG | Closed-world dependency validation and deterministic topology analysis |
| Cross-module overwrite | Relative path normalization and hierarchical ownership conflict rejection |
| Agent widens ModuleSpec scope | System overwrites plan-owned identity, dependency, path, interface, platform and criterion fields |
| Partial publication | One event-store transaction for project plus every task and outbox event |
| Retry duplicates model work | Stable invocation IDs and artifact-first recovery |
| Cross-project artifact read | Tenant/project included in projection lookup and verified on decode |

Semantic plans still require Global Audit; structural validation does not prove that natural-language responsibilities are complete.
