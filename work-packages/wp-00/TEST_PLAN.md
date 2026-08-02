# WP-00 Test Plan

1. Compile every Go package and command.
2. Run all unit tests with race detection where supported.
3. Reject formatting or vet failures.
4. Parse and validate all committed JSON documents and schema metadata.
5. Verify required repository paths, ADR sections, requirement IDs, and CODEOWNERS rules.
6. Scan tracked content for credential-shaped values and forbidden skipped-test markers.
7. Verify declared third-party dependencies and licenses.

All checks run through `make verify` and fail closed.
