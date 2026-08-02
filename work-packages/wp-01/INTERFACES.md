# WP-01 Interfaces

## Go Packages

- `pkg/aop`: envelope, intent, spec references, sender, trace, budget, validation, and canonical digest.
- `pkg/cloudevents`: CloudEvents 1.0 envelope and AOR naming validation.
- `pkg/errors`: stable error codes and redacted Problem Details.
- `internal/contracts`: repository Schema and example validation.

## Documents

- `api/openapi/openapi.yaml`: HTTP API 3.2.0.
- `api/asyncapi/asyncapi.yaml`: domain event API 3.1.0.
- `api/a2a/agent-card.v1.schema.json`: signed A2A Agent Card subset.
- `api/aop/envelope.v1.schema.json`: AOP metadata extension.
- `api/json-schema/*.schema.json`: versioned domain contracts.

All validators return stable AOR error codes and do not mutate input. Time is RFC3339 UTC; identifiers are opaque and unguessable at issuance.
