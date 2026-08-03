# WP-13 Operations

Supply TLS endpoints for traces, metrics, application logs and audit logs to the collector. The audit endpoint and exporter must use a separate access policy and storage class. Admission verifies compliance-mode object lock, versioning, encryption, authenticated time and at least 400 days retention.

Monitor collector refusal/export failure, queue utilization, dropped spans, `__overflow__` label frequency, audit append failures, signature verification, chain-head continuity and clock uncertainty. Audit append failure is a security incident; side-effecting operations whose audit is mandatory fail closed. A broken chain is quarantined without rewriting history.

Run all alert drills quarterly and after material rule/routing changes. Each drill records the injected signal, alert fire time, notification receipt, operator, outcome and evidence digest. Backup restore remains monthly and disaster recovery remains quarterly under WP-14. Dashboard cost investigation starts with bounded provider/model/project metrics, then uses the structured log table for exact Project, Role, Model, Task and Attempt.
