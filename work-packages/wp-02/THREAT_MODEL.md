# WP-02 Threat Model

## Assets

State authority, approved Goal identity, event history, attempt history, idempotency results, approvals, outbox delivery, tenant scope, and completion evidence.

## Threats And Controls

| Threat | Control |
|---|---|
| Agent forges a transition | closed command/transition tables in deterministic reducer |
| Lost update | expected aggregate version and database compare-and-append |
| Duplicate permanent effect | principal/key/request digest record in the same transaction |
| Database-to-bus gap | transactional outbox |
| Event replay conflict | event ID and aggregate-version uniqueness plus payload digest |
| Stale spec submission | exact active spec version and digest guards |
| Old Lease wins race | monotonic fencing token guard supplied to reducer and constrained in storage |
| Attempt reset erases history | immutable attempt series and signed user decision reference |
| Third failure auto-retries | terminal user-blocked transition and frozen dependants |
| Cross-tenant row access | tenant keys, composite references, RLS migration, scoped store API |
| Completion forgery | computed predicate over integrated state and verified evidence only |

The in-memory adapter is test infrastructure and is not a production persistence profile.
