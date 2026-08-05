# WP-11 Threat Model

## Assets

- Signed policies, curated project knowledge, immutable revision history, manifests, trust labels, references, and derived indexes.

## Threats and controls

| Threat | Control |
|---|---|
| Cross-project discovery or read | Tenant/project keys on every operation, principal-scope check, trusted scope resolver, WP-03 policy evaluation, and effective-view membership checks |
| Stale reference silently reads current bytes | Scope and source revisions plus normalized SHA-256 are mandatory; missing revisions return an explicit error |
| Non-Curator or unapproved update | Independent Curator type/role check plus WP-03 approval, lease, task, proposal-digest, and policy validation |
| Approval replay for changed content | Canonical proposal digest binds documents, deletes, overrides, ordered parents, and base revision |
| Traversal or alternate path syntax | Strict relative slash-path normalization and Windows reserved-name checks |
| Symlink, junction, reparse, device, pipe, or socket escape | Component-by-component creation, `Lstat` checks, irregular-mode rejection, containment checks, and immutable-tree verification |
| Multi-parent ambiguity | Explicit order, pinned revisions, duplicate/cycle checks, and conflict rejection |
| Low-trust content masks policy | Override trust must be at least the maximum inherited trust |
| On-disk revision mutation | Complete metadata/content hash verification and canonical revision digest before use |
| Index poisoning | Indexes are derived only from verified immutable snapshots and can be rebuilt |

## Residual risks

- Filesystem compare-and-swap is process-local; horizontally scaled Curator writers require an external single-writer/lock service.
- Windows junction/reparse behavior needs adversarial tests on supported Windows hosts.
- OS ownership, mount flags, backup immutability, retention, and restore correctness are deployment controls.
- The immutable filesystem commit and PostgreSQL outbox transaction cannot share one storage transaction. A failed publication makes the update call fail; retry recognizes the exact committed snapshot, rebuilds its index, and publishes the event idempotently before reporting success.
