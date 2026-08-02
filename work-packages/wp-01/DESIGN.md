# WP-01 Design

Contracts are source-first JSON/YAML documents with mirrored Go types. JSON Schema is authoritative for wire shape; Go semantic validators enforce relationships that cannot be expressed clearly in structural Schema.

AOP uses A2A metadata key `urn:aor:aop:v1`. Core envelope identity, timing, sender, intent, version, artifacts, knowledge, budget, and trace fields are fixed. Spec references are conditional: Goal intents do not fabricate Plan or Module references; later intents require the references established at their lifecycle stage.

Digests are lowercase `sha256:<64 hex>` values over RFC 8785 canonical JSON content. Digest and signature envelope fields are excluded from the content digest. Unknown JSON object fields are accepted only where compatibility explicitly permits them; unknown intent values always fail.

OpenAPI and AsyncAPI reference shared JSON Schemas rather than redefining semantics. Error responses use Problem Details plus a stable AOR code.
