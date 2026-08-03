# Release Conformance

`aor-conformance run --profile test --spec-version 2.0.0 --output ./release-evidence` emits a signed-or-explicitly-unsigned machine-readable report. Production runs require `AOR_RELEASE_SIGNING_KEY` or an injected KMS signer and reject external environment gates, exceptions, and skipped groups.
