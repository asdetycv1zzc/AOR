# Knowledge Plane

Global templates and Schemas live here. Deployed project knowledge is versioned and writable only by the approved Knowledge Curator identity; all Agent access uses Knowledge Service references.

Runtime data is not stored in this source directory. `internal/knowledge.FileRepository` owns an isolated deployment root with immutable revision directories and an atomic `HEAD` pointer per tenant/project. Agents must use `Search` followed by `ReadRange`; they must never open a returned `localPath` directly.

Operational requirements:

- Run the Knowledge Service with read-only access to revision directories.
- Give the Curator update process the only routine write identity and require WP-03 approval plus a capability lease.
- Keep the configured root on one filesystem so revision and `HEAD` renames remain atomic.
- Do not garbage-collect revisions while references or evidence may still point to them.
- Rebuild derived search indexes from immutable revisions after recovery.
