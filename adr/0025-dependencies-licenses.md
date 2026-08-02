# ADR-0025: Dependencies, Licenses, And Third-Party Risk

## Context
Third-party code affects reproducibility, vulnerability exposure, licensing, and operational continuity.

## Decision
Minimize dependencies, pin exact versions and checksums, generate an SBOM and notices, and allow only approved licenses. Critical dependencies require ownership, maintenance review, and a documented replacement path.

## Alternatives
Unpinned or dynamically downloaded production dependencies cannot be reliably audited. Reimplementing mature security protocols creates avoidable risk.

## Security Consequences
Critical vulnerabilities block release; High issues must be fixed within seven days and cannot be waived at production release under the baseline.

## Operational Consequences
Automated inventory, license, provenance, and vulnerability gates run before release.

## Migration
Dependency changes include compatibility, license, security, and rollback evidence in the same submission.

## Status
Accepted
