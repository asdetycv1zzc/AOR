# WP-11 Knowledge Module Specification

- Task ID: `WP-11`
- Phase: `3`
- Dependencies: `WP-03`, `WP-05`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Provide project-scoped knowledge discovery and exact, immutable line-range reads without granting Agents direct filesystem access.

## Responsibilities

- Store normalized UTF-8/LF documents in immutable content-addressed revisions.
- Return exact source revision, normalized SHA-256, trust, and 1-based inclusive line references.
- Maintain exact path/title/tag and full-text indexes derived from source revisions.
- Resolve only explicit, ordered, revision-pinned project inheritance.
- Require a Knowledge Curator identity, approval, capability lease, and WP-03 allow decision for atomic updates.
- Reject traversal, symlink, junction/reparse-like, irregular-file, conflict, and trust-downgrade paths.

## Non-responsibilities

- Agent scheduling, approval issuance, capability lease issuance, model context assembly, revision garbage collection, and production event signing.

## Allowed paths

`internal/knowledge/`, `knowledge/`, and `work-packages/wp-11/`.

## Acceptance criteria

1. Search and reads fail closed when identity scope, trusted project scope, or policy evaluation is unavailable or denied.
2. Old references read the old normalized bytes after a later update, or return `AOR_KNOWLEDGE_REVISION_NOT_AVAILABLE` when that revision is absent.
3. Reads return at most 200 lines and 32 KiB per page with an explicit next line.
4. Unrelated projects cannot enumerate or read documents; inherited documents remain pinned to declared parent revisions.
5. Multi-parent path conflicts require an explicit child override whose trust does not downgrade inherited content.
6. Only an approved and leased Curator update can atomically advance a project's `HEAD`.

## Evidence boundary

Focused unit, race, and vet checks exercise the in-process service and filesystem repository. Multi-process writer serialization, real Windows junction/reparse adversarial tests, signed update events, backup/restore drills, and deployed OS service-account permissions remain release-level evidence and are not claimed by this work package.
