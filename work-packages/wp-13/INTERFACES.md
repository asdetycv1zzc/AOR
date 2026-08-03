# WP-13 Interfaces

## Application telemetry

- `Correlation.Validate` enforces identifier-or-reason semantics.
- `Logger.Emit` writes one bounded JSON application record to `ApplicationSink`.
- `ParseTraceParent`, `ExtractTrace`, `InjectTrace`, `ContextWithTrace` and `TraceFromContext` implement W3C propagation.
- `Tracer.Start` and `Span.End` emit the fixed SPEC span names to `TraceSink`.
- `RetentionSampler.ShouldSample` always retains specified critical outcomes.
- `MetricRegistry.Record` validates a registered descriptor and cardinality budget before calling `MetricSink`.

## Security audit

- `AuditLog.Append` validates, sanitizes, timestamps, hashes, signs and appends an event.
- `AuditLog.Query` records the reader and bounded reason code before querying by Project, Task, Principal, Artifact, Approval or type.
- `AuditStore` deliberately exposes no update or delete operation.
- `VerifyAuditChain` verifies sequence, previous hash, record digest and signature.
- `ValidateSinkSeparation` rejects equal application and audit destinations.

`HMACAuditSigner` and `FileAuditStore` support tests and local operation. Production adapters implement `AuditSigner` using KMS/HSM signing and `AuditStore` using compliance-mode object lock or an equivalent immutable ledger.
