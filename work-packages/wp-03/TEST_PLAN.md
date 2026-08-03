# WP-03 Test Plan

1. Validate all principal types, malformed IDs, SPIFFE path components, exact trust domains/environments, and OIDC issuer/audience/subject/time/revocation cases.
2. Verify authenticator context cancellation and verifier errors remain redacted and cannot produce a principal.
3. Table-test read, repository, knowledge, policy, deployment, and unknown actions for role, state, path, approval, and lease requirements.
4. Verify malformed input, unavailable bundles, missing/expired/revoked/tampered leases, mismatched bindings, and stale fencing tokens always deny.
5. Issue leases, renew concurrently, heartbeat, revoke, expire, and verify old copies fail after fencing changes.
6. Verify parameter digest and resource path changes cannot reuse a lease.
7. Verify policy decisions have stable JSON fields and never expose signing keys, bearer tokens, or arbitrary policy output.
8. Run race-enabled tests and `go vet ./...`.
