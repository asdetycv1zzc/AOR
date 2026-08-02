# ADR-0018: SLSA, SBOM, Signing, And Release

## Context
Release consumers need verifiable binding between source, builder, dependencies, artifacts, and approvals.

## Decision
Build Linux artifacts in ephemeral controlled containers and trusted Windows artifacts on native runners reporting `NONE`. Produce SPDX or CycloneDX SBOM, SLSA 1.2 provenance/in-toto attestations, content-addressed manifests, and Sigstore or KMS signatures.

## Alternatives
Checksums without builder identity do not establish provenance. Mutable tags are not release identities.

## Security Consequences
Signing keys are unavailable to Agents and build steps until required. Production needs distinct platform and security approvals bound to the release digest.

## Operational Consequences
Reproducibility, signer availability, transparency records, revocation, and offline verification need runbooks.

## Migration
Attestation formats are versioned and old verification roots remain available for retained releases.

## Status
Accepted
