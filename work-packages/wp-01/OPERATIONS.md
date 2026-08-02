# WP-01 Operations

Contract publication is content-addressed. CI validates every Schema, example, fixture, OpenAPI operation, AsyncAPI message, and Go representation. A compatibility failure blocks dependent services and release.

Unsupported versions and unknown required capabilities return a non-retryable compatibility error. Malformed or oversized payloads are rejected before logging their content.
