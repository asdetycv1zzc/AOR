# Interfaces

- `Check` is a deterministic, side-effect-free audit check.
- `AuditorFactory.New` creates a new auditor per run.
- `EvidenceStore` is immutable and keyed by project, task and attempt.
- `HMACSigner` is a test signer; production uses KMS or Sigstore-backed signing.
