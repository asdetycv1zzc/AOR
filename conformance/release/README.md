# Release Conformance

`aor-conformance run --profile test --spec-version 2.0.0 --output ./release-evidence` emits a signed-or-explicitly-unsigned machine-readable report. When `--target` is set, the runner independently reads `/health/ready` and `/version`, rejects a build identity that does not match the requested release, and stores the bounded raw HTTP exchanges under `raw/`. Their SHA-256-bound references are included in every result so local deterministic evidence cannot be attributed to another deployment. Production targets require HTTPS and an output directory. Local test runs record unavailable external environment groups as exceptions; preproduction and production runs fail closed until those groups execute. Production runs require `AOR_RELEASE_SIGNING_PRIVATE_KEY_FILE` plus `AOR_RELEASE_SIGNING_KID`, or an injected KMS signer. `AOR_RELEASE_SIGNING_KEY` is retained only for local HMAC evidence and is rejected for production.

## Offline package gate

The release package is assembled by `aor-release` from a versioned JSON input document. The input must name every binary, OCI image export, deployment package, locked material, dependency license text, and the signed production `release-evidence.json`. Assembly writes SPDX 2.3 SBOM and SLSA 1.2/in-toto provenance, signs every package entry and the manifest with Ed25519, and verifies the complete package before publishing the output directory.

```bash
go run ./cmd/aor-release assemble --config ./release-input.json
go run ./cmd/aor-release verify --root ./dist/aor-release --public-key ./release-public.pem
```

The verifier is offline and rejects missing or symlinked files, path traversal, digest changes, unsigned entries, incomplete SBOM file coverage, provenance whose source/builder/material/subject set differs from the manifest, and release evidence that is not a production all-PASS report. The trusted public key is supplied out of band; it must not be taken from the package being verified.

`api/json-schema/release-input.v1.schema.json` and `api/json-schema/release-manifest.v1.schema.json` are the machine-readable input and output contracts. Production key files must be owner-readable only. A release workflow is still required to provision the signing key/KMS identity, build OCI exports, run vulnerability and IaC scanners, deploy preproduction, and attach two-person approval evidence; local package tests do not satisfy those environment gates.

## Independent environment driver

External groups can be supplied to the runner with `--driver-manifest <file> --driver-public-key <file>` (or `AOR_CONFORMANCE_DRIVER_MANIFEST` and `AOR_CONFORMANCE_DRIVER_PUBLIC_KEY_FILE`). The manifest is a signed JSON document that binds the driver executable and signed corpus digests to the exact target, source commit, release, build digest, tenant, namespace, and requested groups. The runner never executes a shell: it verifies the executable digest, starts the signed executable with a bounded timeout and stdout/stderr limit, and passes the target and isolation scope through `AOR_CONFORMANCE_*` environment variables.

The executable must emit one JSON result for every requirement owned by each requested external group. Reliability and performance groups therefore produce multiple results, and `full` owns every SPEC requirement not already assigned to another requested group. Each result carries one or more `trace`, `log`, or `artifact` references. The runner reads only regular files below `AOR_CONFORMANCE_EVIDENCE_DIR`, verifies every declared SHA-256, copies the bounded bytes into a requirement-specific path under `raw/external/`, and binds the resulting `file:` references to release evidence. It lists every missing requirement in `uncoveredRequirements`; Production requires that list to be empty. Production additionally requires Ed25519 signatures on the manifest, corpus digest, and driver result; a target health/version response is never accepted as an external group PASS.
