# WP-07 Operations

## Required signals

- Active slots, waiters and queue age by role group.
- Lifecycle transition counts and age in each nonterminal state.
- Lease validation, heartbeat, renewal, expiry and post-call rejection counts.
- Model/tool duration, cancellation and dependency failure counts by normalized provider/tool ID.
- Prompt/context integrity rejection and blind-audit contamination counts.
- Agent Card signature and protocol downgrade failures.

## Alerts

- Active slots exceed eight: page immediately and stop scheduling.
- Three-heartbeat expiry rate, queue p99 or post-call rejection rate exceeds the deployment threshold.
- Any credential-pattern rejection or blind-audit violation emits a security event.
- Runtime accepts work while the authoritative SlotAllocator, LeaseAuthority, Gateway or Broker is unavailable: page immediately; expected behavior is fail closed.

## Logging

Log run, tenant, project, task, role, message, correlation, trace, lease, prompt/context digests and normalized error code. Do not log Prompt text, model/tool bodies, repository content, private scratchpads, credentials, PII or hidden-test data. GenAI content telemetry remains disabled by default.

## Recovery

After a restart, rebuild Runtime views from WP-02 AgentRun state and resume only after current lease and AOP bindings validate. Do not replay provider or tool operations from in-memory state. Reconcile unknown provider billing through Model Gateway before retry.

