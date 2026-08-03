# WP-04 Design

`Gateway` owns adapter lookup, request validation, reservation lifecycle and response normalization. `BudgetLedger` is mutex-protected in-memory infrastructure for tests and local mode; the same interface can be backed by PostgreSQL. Adapters receive an opaque provider credential only inside the gateway call. Cache keys are canonical JSON digests over all policy and model-version inputs.
