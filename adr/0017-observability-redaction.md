# ADR-0017: OpenTelemetry, Redaction, And Audit Logs

## Context
AOR needs end-to-end correlation without leaking prompts, source, secrets, personal data, or hidden tests.

## Decision
Use OpenTelemetry traces, metrics, and structured logs with bounded identifiers. Model and tool content fields default off. Apply shared redaction before export and store immutable security audit logs separately from application logs.

## Alternatives
Provider-specific telemetry fragments investigations. Recording full content creates unacceptable exposure.

## Security Consequences
Errors, third-attempt blocks, policy denials, and budget denials are always sampled without sensitive body data. Exporters use workload identity.

## Operational Consequences
Cardinality budgets, schema validation, retention, access control, and redaction tests are required.

## Migration
Telemetry schemas are versioned; additive fields are preferred and renamed fields overlap during migration.

## Status
Accepted
