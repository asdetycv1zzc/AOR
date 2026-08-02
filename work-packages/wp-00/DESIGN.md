# WP-00 Design

The bootstrap is a single Go module with standard-library-only production code. External infrastructure is represented by versioned contracts and deployment manifests until its owning work package implements an adapter. This keeps the first build reproducible and prevents dependency choices from silently fixing later architecture.

Repository ownership follows `SPEC.md` section 36. CI calls the same `make verify` entry point used locally. ADRs are immutable numbered records; later decisions supersede rather than rewrite accepted history.

Security-sensitive directories are owned separately in `CODEOWNERS`. All configuration examples contain secret references only. Release and production acceptance remain explicitly unsigned until Phase 7 evidence exists.
