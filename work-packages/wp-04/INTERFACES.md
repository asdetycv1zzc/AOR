# WP-04 Interfaces

The public contract is the `internal/modelgateway` package:

- `ModelAdapter` implements capabilities, token counting, generation, streaming, cancellation and usage normalization.
- `Gateway.Generate` validates a `NormalizedRequest`, reserves budget, invokes an adapter, validates structured output and settles usage.
- `BudgetLedger` exposes `Reserve`, `Settle`, `Release` and `Reconcile`.
- `CacheKey` returns a content-addressed key with model, prompt, tool, policy and classification inputs.
