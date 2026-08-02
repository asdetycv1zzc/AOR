# WP-00 Threat Model

## Assets

Source history, build rules, protocol contracts, policy files, hidden-test boundaries, release metadata, and contributor identities.

## Threats And Controls

| Threat | Control |
|---|---|
| CI or build bypass | One fail-closed `make verify` path and protected workflow ownership |
| Credential committed to source | Secret-reference-only configuration and deterministic secret scan |
| Dependency substitution | Exact toolchain pinning, lock files, checksums, SBOM gate |
| Policy or hidden-test tampering | Separate ownership and forbidden Executor paths |
| False production claim | Unsigned acceptance checklist and explicit development status |
| Requirement drift | Versioned SPEC reference and machine-readable traceability catalog |

## Trust Boundary

Repository content and generated output are untrusted inputs. CI results become evidence only when produced by an approved builder and bound to a commit digest.
