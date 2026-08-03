# Operations

Use a dedicated workspace volume with mode `0700`, periodic orphan cleanup keyed by terminal task state, and no shared Docker or Git credentials. A failed commit leaves the workspace for evidence and never creates a Submission record.
