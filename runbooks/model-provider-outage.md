# Model Provider Outage

Severity: SEV-2. Alert: provider error-rate, circuit-breaker, or `AORProviderResultUnknown` alert.

Symptoms: timeouts, rate limits, or unknown stream outcomes. Containment: let the Model Gateway circuit breaker open, stop blind retries, and preserve reservations requiring reconciliation.

Diagnosis: inspect provider health, request IDs, model-call status, reservation state, and provider policy. Never retrieve or print an API key; verify only the secret reference and key age.

Recovery: wait for the bounded retry window or route to an explicitly approved compatible candidate. Reconcile every unknown call before releasing budget and keep role capability floors intact.

Verification: confirm no reservation overrun, no duplicate non-idempotent call, authoritative usage for completed streams, and deterministic replay for completed requests.

Evidence: retain provider request IDs, circuit state, usage reconciliation, policy digest, and traces. Retrospective: update outage thresholds and provider capacity assumptions.
