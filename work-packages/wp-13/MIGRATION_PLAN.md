# WP-13 Migration Plan

Introduce correlation validation in report-only mode for one release while counting invalid producers, then make invalid logs fail closed after every service supplies identifiers or reasons. Run the application and audit collector endpoints in parallel before routing security audit traffic; compare record counts and chain heads during cutover. Enable bounded metric descriptors before removing legacy high-cardinality series, and retain overlapping recording rules for one dashboard release.

Create the immutable audit destination with object lock before the first Production record. Retention may be increased without migration; reducing it requires a new ADR and compliance approval. Signing-key rotation records a signed key-rotation event and preserves old verification keys. Rollback may restore exporters and dashboards but must never co-locate audit/application logs, delete immutable records or disable critical trace retention.
