# Interfaces

- `Queue.Audit` returns stable, structured integration findings.
- `Queue.Merge` requires a passing audit and delegates the side effect to `MergeExecutor`.
- `MemoryStore` models the immutable/idempotent result contract for tests; production uses the event store.
