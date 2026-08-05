# Observability

OpenTelemetry collectors, bounded-cardinality dashboards, alert rules, and SLO definitions live here. Model, prompt, code, hidden-test, and tool content telemetry defaults off.

- `otel-collector.yaml` accepts application telemetry on `4317`/`4318` and audit records on the separate `4327`/`4328` endpoint. The four exporter endpoints must be supplied through environment references.
- `otel-collector.compose.yaml` keeps the same ingress separation, redaction, and mandatory trace-sampling rules but uses basic debug exporters so the local Compose profile starts without an external observability backend. It is not durable telemetry storage.
- `prometheus-rules.yaml` contains SLO recording rules and every alert required by SPEC section 24.6.
- `fault-drills.yaml` maps each required alert to a controlled drill and defines the evidence record required after execution.
- `grafana-dashboard.json` uses bounded metrics for fleet views and structured logs for project/task cost drill-down.
- `audit-storage-policy.yaml` is the deployment contract for the audit-only object store. Production admission must reject storage without compliance-mode object lock and at least 400 days retention.

The Go package rejects raw identifier labels. `project` is a controlled metric dimension with overflow aggregation; exact Project, Task and Attempt investigation uses redacted structured logs and traces.
