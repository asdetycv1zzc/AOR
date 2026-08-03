# WP-11 Design

## Source of truth

Each tenant/project has a `HEAD` pointer and immutable revision directories. A revision is the SHA-256 of canonical manifest facts, normalized metadata, and normalized document bytes. The repository writes a private staging tree, syncs files, renames the complete revision, then atomically renames `HEAD`. Old revision directories are never modified or deleted by updates.

## Service boundary

Every public operation resolves trusted project/task state through `ScopeResolver` and evaluates an `authz.PolicyInput`. Reads use `knowledge.read`. Writes use `knowledge.write` and additionally require the exact proposal digest, Curator principal type and role, approval, lease, task scope, and budget account. Authorization is repeated immediately before commit.

## Retrieval

An indexed view is keyed by tenant, project, and exact scope revision. It contains exact path, title, and tag lookups plus a Unicode-aware full-text n-gram index. Search caps results at 20 and defaults to 8. A reference records both the child's scope revision and the immutable source project/revision so inherited references remain verifiable.

`ReadRange` resolves that exact scope revision, confirms the source project, revision, path, SHA-256, URI, encoding, line ending, media type, title, and trust, then returns an inclusive page. Curated input rejects a line larger than 32 KiB, allowing pagination to preserve line semantics.

## Inheritance

Direct parents are an ordered list of exact revisions. More than one parent requires an explicit-order flag. Effective views recursively resolve those snapshots, reject cycles and ambiguous paths, and allow a conflict only when the child declares and provides an override. An override cannot lower the highest inherited trust level.

## Filesystem defense

Logical paths reject absolute paths, traversal, backslashes, drive separators, controls, trailing dot/space, and Windows reserved names. Root and project creation walk one component at a time. Reads and writes use `Lstat`, reject links and irregular objects, and verify every stored byte and metadata field against the revision digest. Deployment permissions remain a necessary second boundary.
