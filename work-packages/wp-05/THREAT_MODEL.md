# WP-05 Threat Model

| Threat | Control |
|---|---|
| Tool bypasses authorization | Broker is the only executor entry point and requires lease + policy |
| Prompt/tool injection | Tool output is untrusted and schema/size checked |
| Secret exfiltration | Output redaction and no credential field in request |
| SSRF | URL validator rejects loopback, private, link-local and metadata destinations |
| Stale permanent approval | Revalidation callback runs immediately before execution |
