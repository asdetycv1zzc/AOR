# WP-04 Threat Model

| Threat | Control |
|---|---|
| Credential disclosure | Credentials are supplied by a private provider and never part of request/response types |
| Budget exhaustion | Worst-case reservation precedes adapter invocation; hard limits fail closed |
| Duplicate charging | Reservation and settlement keys are idempotent |
| Cross-class cache leak | Classification and tenant/project scope are part of the cache key |
| Provider output injection | Size, UTF-8, JSON and schema checks precede returning output |
