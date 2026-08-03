# WP-11 Migration Plan

## Initial deployment

1. Provision a dedicated knowledge root on one filesystem with Curator-only write ownership.
2. Deploy Knowledge Service with read-only revision access and no direct Agent mount.
3. Configure the trusted project/task scope resolver and WP-03 policy evaluator.
4. Import each project as one normalized, approved initial proposal.
5. Record the returned revision and rebuild its index.
6. Compare document counts and sampled hashes before enabling search traffic.

## Upgrade

Revision format version 1 is immutable. A future format writes new revisions alongside version 1 and keeps the old reader until all retained references expire. Never rewrite a revision in place.

## Rollback

Advance `HEAD` through an approved proposal that reproduces the prior desired content and parents. Do not move or edit immutable directories manually. If the service binary is rolled back, retain every revision and rebuild only the derived index.

## Existing unversioned trees

Treat imports as untrusted input: reject links/reparse-like objects, normalize UTF-8/LF, require explicit metadata/trust, review conflicts, and obtain Curator approval before the atomic initial commit.
