# WP-13 Design

The package keeps telemetry data typed at the process boundary. `Logger` emits only structured attributes after correlation validation, content-key removal, secret/PII redaction and deterministic bounding. `Tracer` carries a strict W3C version-00 context and exports named spans through a tail-retention sampler. `MetricRegistry` accepts only registered descriptors, rejects identifier labels and maps excess label values or series to `__overflow__`.

Audit records do not use the application-log sink. `AuditLog` obtains a source-labelled trusted timestamp, links each record to the prior hash, signs the new digest and calls an append-only store interface. Querying through `AuditLog.Query` appends `AUDIT_LOG_READ` before returning records. The local file store is a durable single-process adapter; Production uses an audit-only backend satisfying `audit-storage-policy.yaml`.

Fleet metrics remain bounded. Exact Project, Role, Model, Task and Attempt cost investigation uses redacted structured logs and traces, which avoids placing Task and Attempt identifiers in ordinary metric labels.
