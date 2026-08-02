# WP-01 Test Plan

1. Validate positive and negative fixtures for every JSON Schema.
2. Round-trip AOP, CloudEvents, errors, approvals, and spec references through Go JSON serialization.
3. Verify each known Intent and reject unknown Intent values.
4. Verify unknown optional fields survive or are ignored as specified; reject unknown required extensions.
5. Verify conditional Goal, Plan, Module, and Task references by Intent.
6. Verify canonical digest stability across object key order and rejection on content change.
7. Verify time window, attempt range, expected version, sender, trace, and URI constraints.
8. Lint OpenAPI/AsyncAPI versions, unique operations/messages, shared error shape, idempotency, and ETag declarations.
9. Run A2A/AOP compatibility fixtures and Go/TypeScript/Python serialization fixtures.
