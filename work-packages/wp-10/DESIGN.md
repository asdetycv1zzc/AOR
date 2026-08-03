# Design

`audit.Pipeline` executes an ordered check list, records every check with ordinal, tool digest and result hashes, and only creates a fresh Auditor after all deterministic checks pass. The Auditor receives immutable commits, changed paths, module references and deterministic evidence only.
