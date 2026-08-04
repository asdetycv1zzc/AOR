# Budget Reconciliation

Severity: SEV-1 for unexplained spend. Alert: `AORBudgetLedgerMismatch` or cost drift.

Symptoms: a ledger does not match model/tool attempts, a reservation is stale, or provider usage is unknown. Containment: freeze affected budget accounts and deny new calls; never edit ledger rows directly.

Diagnosis: compare reservation, claim, attempt, provider request ID, usage, and settlement records using their immutable digests. Check duplicate idempotency keys and the account scope.

Recovery: run the approved provider reconciliation job, settle only authoritative usage, and release or retain reservations according to the outcome-known policy. Escalate unresolved calls to a human budget owner.

Verification: recompute every account balance from the append-only records and confirm zero unexplained calls and permitted rounding error.

Evidence: save the reconciliation report, provider receipts, account snapshots, approvals, and trace IDs. Retrospective: document the accounting gap and prevention test.
