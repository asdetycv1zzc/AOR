# WP-11 Test Plan

## Automated focused tests

1. Normalize CRLF to LF and preserve exact old revision reads after a newer commit.
2. Enforce 1-based inclusive pages at 200 lines and 32 KiB.
3. Exercise exact path/title/tag and full-text retrieval with default/max caps.
4. Prove unrelated project isolation and principal project-scope denial.
5. Pin child inheritance while the parent advances to a later revision.
6. Reject implicit multi-parent order, unresolved conflicts, and trust downgrades; accept an explicit Curator resolution.
7. Fail closed for missing authorizer, non-Curator writes, missing approval, policy denial, and unsafe paths.
8. Reject symlink roots, project-path escapes, and tampered revision content.
9. Rebuild indexes from immutable source with trust labels intact.
10. Integrate a real WP-03 engine, approval verifier, signed capability lease, and exact proposal binding.

## Required commands

```text
go test ./internal/knowledge
go test -race ./internal/knowledge
go vet ./internal/knowledge
```

## Release-level tests not claimed here

- Native Windows junction/reparse corpus.
- Multi-process and network-filesystem writer contention.
- Backup/restore plus unavailable-revision retention drills.
- Large-corpus retrieval latency/load thresholds.
- Signed event and deployed service-account permission tests.
