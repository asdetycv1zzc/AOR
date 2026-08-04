# Knowledge Corruption

Severity: SEV-2, SEV-1 when cross-project data is exposed. Alert: knowledge revision/hash or isolation alert.

Symptoms: a revision hash fails, an index differs from its immutable snapshot, or a project sees an unauthorized document. Containment: disable curator publication and knowledge writes, pin readers to the last verified revision, and preserve the affected repository.

Diagnosis: compare manifest, revision, document hashes, tenant/project scope, inheritance declarations, and access traces. Check for symlink or path traversal attempts.

Recovery: restore the last signed revision, rebuild the index from immutable content, and require curator approval before publication. Revoke leases used by an unauthorized writer.

Verification: run revision-pinned reads, cross-tenant enumeration tests, and deterministic index comparison.

Evidence: retain revision and document digests, access decisions, curator approval, and traces. Retrospective: record the source and add a corpus regression.
