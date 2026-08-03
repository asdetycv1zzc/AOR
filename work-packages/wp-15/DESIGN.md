# Design

The runner executes deterministic local checks and records environment-gated groups as explicit exceptions. Production profiles require a signer and zero exceptions. Evidence is written with a temporary file and atomic rename, and its digest excludes the signature field.
