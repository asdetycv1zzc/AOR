# WP-13 Test Plan

1. Reject every correlation combination where an identifier and reason conflict or both are empty.
2. Inject Prompt, code, hidden-test, credential, e-mail, IP and oversized attributes; inspect the exact serialized sink payload.
3. Parse valid and malformed W3C headers and simulate one trace across project, model, tool, repository and audit spans.
4. Set normal sampling to zero and assert errors, third failures, security denials, budget denials and critical traces remain.
5. Validate all required metric descriptors, reject raw identifier labels and force label/series overflow.
6. Mutate every signed audit-record field, break sequence/previous hash and verify failure; race concurrent appends under `go test -race`.
7. Parse all shipped YAML/JSON, require distinct application/audit pipelines, map every mandatory alert to a drill and verify cost dashboard dimensions.
8. In preproduction, execute every `fault-drills.yaml` scenario through the real notification path and retain signed evidence for at least 400 days.
9. In WP-15, run the secret/PII corpus, collector load/cardinality tests, exporter outage tests, WORM delete denial and end-to-end trace query.
