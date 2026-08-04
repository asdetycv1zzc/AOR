# Security Corpus

`manifest.json` binds every reviewed fixture to corpus version `1.0.0` and to the
acceptance requirements it supports. Each fixture uses schema version 1 and
contains sorted, globally unique cases with an explicit attack vector, payload,
expected fail-closed decision, and protected invariant.

The machine gate rejects missing mandatory categories or vectors, version drift,
unknown fields, duplicate identifiers, symlinks, and unreviewed JSON files. Run
it with:

```text
go run ./cmd/aor-conformance security-corpus
```

Corpus validation is local regression evidence. It does not replace live Linux
container, hostile peer, DNS, timing, or cross-tenant acceptance gates. Every
confirmed security incident must add a permanent case and increment the corpus
version when its format or interpretation changes.
