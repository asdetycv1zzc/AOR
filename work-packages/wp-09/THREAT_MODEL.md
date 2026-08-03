# Threat Model

Controls cover path traversal, symlink escape, unowned changes, Git hooks, detached-head confusion, stale leases, cross-tenant workspace paths, oversized writes, and fabricated manifests. Hard-link and platform reparse-point tests remain deployment gates for native filesystems.
