# WP-11 Operations

## Health checks

- Resolve a known project `HEAD` and verify its manifest/revision digest.
- Rebuild a sampled index and compare document counts.
- Run an authorized exact-path search and range read without opening `localPath` directly.

## Alerts

- Any `AOR_ARTIFACT_HASH_MISMATCH`, inheritance cycle/conflict on a previously healthy revision, or unsafe-path rejection against stored data is a security signal.
- Sustained `AOR_KNOWLEDGE_REVISION_NOT_AVAILABLE` indicates retention or restore failure.
- Repeated base-version conflicts indicate multiple Curator writers or a stuck client.
- Index rebuild failures require serving only an already verified immutable cache or failing closed.

## Recovery

1. Stop Curator writes while leaving immutable reads available when verified.
2. Restore missing revision directories and `HEAD` from a verified backup.
3. Run full revision verification before rebuilding indexes.
4. Confirm pinned parent revisions exist for every restored child.
5. Resume writes only after ownership and policy/lease dependencies are healthy.

## Retention

Do not remove a revision referenced by a child manifest, API reference, audit evidence, or retention policy. Revision garbage collection is intentionally outside this module.

## Horizontal scaling

Read-only Knowledge Service replicas may scale horizontally. Curator commits require one writer for this filesystem implementation until a cross-process compare-and-swap coordinator is deployed.
