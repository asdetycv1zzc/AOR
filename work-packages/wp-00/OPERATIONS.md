# WP-00 Operations

Run `make verify` before review. A failed gate blocks the work package. Build output is written only to ignored local paths. The baseline has no listening service, database, model connection, credential, or permanent external side effect.

CI failures are diagnosed from the first failed gate because gate order is stable. Preserve logs as untrusted diagnostic output; they are not signed release evidence.
