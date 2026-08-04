# WP-04 Interfaces

The public contract is the `internal/modelgateway` package:

- `ModelAdapter` implements capabilities, token counting, generation, streaming, cancellation and usage normalization.
- `Gateway.Generate` validates a `NormalizedRequest`, reserves budget, invokes an adapter, validates structured output and settles usage.
- `Gateway.Stream` reserves the worst-case budget before opening an adapter stream; final stream usage remains in reconciliation until a provider usage record is available. `Gateway.Cancel` is restricted to registered provider/model pairs, while `Gateway.CancelStream` marks a scoped stream reservation for reconciliation before forwarding cancellation.
- `BudgetLedger` exposes `Reserve`, `Settle`, `Release` and `Reconcile`.
- `CacheKey` returns a content-addressed key with model, prompt, tool, policy and classification inputs.
- `HTTPService` exposes strict internal HTTP endpoints: `POST /v1/model/generate`, `POST /v1/model/stream`, `POST /v1/model/cancel`, and `GET /v1/model/capabilities`. Every endpoint requires an injected `HTTPAuthorizer`; transport tenant headers are ignored and the authorizer binds the request to the caller's tenant, workload, provider, and budget account.
