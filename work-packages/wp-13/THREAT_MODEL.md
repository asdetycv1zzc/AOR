# WP-13 Threat Model

| Threat | Control |
|---|---|
| Prompt, source, hidden-test, tool or model content enters telemetry | Semantic content keys are removed before sink invocation; collector repeats deletion as defense in depth |
| Credentials or common PII appear in an allowed value | Shared regex redaction runs before serialization; secret-corpus tests must extend patterns |
| Oversized values exhaust collectors | Attribute count/key/value and final event size are bounded |
| Forged or malformed trace headers corrupt correlation | Strict lowercase W3C version-00 parsing rejects zero IDs, invalid lengths, duplicate/unsafe tracestate and header injection |
| Head sampling drops the only evidence of a failure | Error, third failure, security denial, budget denial and critical outcomes are retained deterministically |
| Metric labels exhaust storage | Raw identifier labels are forbidden; per-label and per-metric series caps aggregate overflow |
| Application operators alter audit history | Audit writes use a separate destination, sequence/hash chain and signature; Production storage requires compliance WORM |
| Audit administrator reads without accountability | Query appends a signed `AUDIT_LOG_READ` event first and fails closed if that append fails |
| Host clock manipulation changes audit ordering | Records carry trusted time source and uncertainty plus monotonic sequence; Production supplies an authenticated time source |

Residual risks requiring WP-15 evidence are collector processor compatibility with the deployed version, complete secret/PII corpus recall, multi-writer audit-store serialization, WORM enforcement, and actual alert delivery during controlled fault drills.
