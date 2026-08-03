# Release Conformance

`aor-conformance run --profile test --spec-version 2.0.0 --output ./release-evidence` emits a signed-or-explicitly-unsigned machine-readable report. Local test runs record unavailable external environment groups as exceptions; preproduction and production runs fail closed until those groups execute. Production runs require `AOR_RELEASE_SIGNING_KEY` or an injected KMS signer.
