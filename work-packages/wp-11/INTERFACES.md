# WP-11 Interfaces

## Service

- `NewService(ServiceConfig) (*Service, error)` requires a repository, WP-03 policy evaluator, and trusted scope resolver.
- `Service.Search(ctx, SearchRequest) (SearchResponse, error)` accepts exact path/title/tag filters and full text; the default/max result limits are 8/20.
- `Service.ReadRange(ctx, ReadRangeRequest) (ReadRangeResponse, error)` validates an immutable reference and pages at 200 lines/32 KiB.
- `Service.Manifest(ctx, Access, revision) (Manifest, error)` returns a requested or current project manifest after read authorization.
- `Service.Update(ctx, Access, UpdateProposal) (UpdateResult, error)` performs approved, leased, atomic Curator updates.
- `Service.RebuildIndex(ctx, Access, revision) (IndexSnapshot, error)` rebuilds derived indexes from an exact immutable source.
- `ProposalDigest(UpdateProposal) (string, error)` creates the normalized digest that approval and lease proofs must bind.

## Storage

- `Repository.Head` resolves only a tenant/project's pointer.
- `Repository.Load` verifies and returns an exact revision.
- `Repository.Commit` compares the expected base revision and atomically publishes a complete snapshot.
- `FileRepository` implements the interface with content-addressed filesystem revisions.

## Reference contract

References include `resourceUri`, `localPath`, `scopeRevision`, `sourceProjectId`, `path`, `revision`, `sha256`, inclusive `lineStart`/`lineEnd`, `utf-8`, `LF`, content type, title, tags, trust, and retrieval score. `localPath` is evidence metadata, not permission for Agent filesystem access.

## Errors

- Missing exact revisions: `AOR_KNOWLEDGE_REVISION_NOT_AVAILABLE`.
- Unauthorized writes: `AOR_KNOWLEDGE_WRITE_FORBIDDEN`.
- Traversal/link/reparse-like paths: `AOR_UNAUTHORIZED_PATH`.
- Modified revision bytes: `AOR_ARTIFACT_HASH_MISMATCH`.
- Parent, override, or trust conflicts: `AOR_CONFLICT`.
- Concurrent base changes: `AOR_STATE_VERSION_CONFLICT`.
