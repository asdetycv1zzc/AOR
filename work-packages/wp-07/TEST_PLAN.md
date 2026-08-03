# WP-07 Test Plan

## Deterministic unit tests

1. Traverse declaration, queue, lease, start, wait/resume and terminal transitions; table-test invalid transitions.
2. Fill all eight active slots, verify a ninth waits, cancel it, and assert no slot leak.
3. Verify role soft-limit preference and aging order under contention.
4. Mutate Prompt Bundle, Context Manifest and item hashes; reject every mutation.
5. Embed delimiter-like injection text and prove it remains an escaped `authority=false` JSON value.
6. Reject credentials, unknown context kinds, trust relabeling and oversized content.
7. Exercise every forbidden Module Auditor context kind.
8. Capture Gateway/Broker calls and compare tenant, project, task, role, lease, policy, budget and digest bindings.
9. Expire a lease during a provider call and reject the returned result.
10. Cancel a blocked provider call and assert prompt release of the active slot.
11. Deny Executor completion intents and unknown intents.
12. Sign, verify, mutate and downgrade Agent Cards.

## Broader verification

- Run `go test -race ./internal/agentruntime`.
- Run the repository test suite and `git diff --check`.
- In integration, use stub providers for deterministic flows, then two real model families as required by Phase 4 exit criteria.
- In conformance, run at least 30 model samples for behavioral rates; security denials require 100% rejection.

