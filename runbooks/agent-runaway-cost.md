# Agent Runaway Cost

Severity: SEV-1. Alert: `AORBudgetGrowthAnomaly` or concurrency saturation.

Symptoms: rapid token/cost growth, recursive task creation, or sustained maximum active agents. Containment: stop new leases for the project, freeze its budget account, and cancel only through the orchestrator.

Diagnosis: group immutable model/tool calls by project, role, task, attempt, model, and idempotency key. Inspect scheduler queue, lease fencing, workflow history, and provider circuit state.

Recovery: terminate the runaway workflow, reconcile unknown calls, and resume with a reduced policy only after an approval record and fresh lease.

Verification: prove the eight-agent and three-attempt limits, zero unexplained calls, bounded queue growth, and no stale holder can write.

Evidence: retain cost timeline, call ledger, traces, approvals, and cancellation results. Retrospective: add the triggering pattern to rate and recursion tests.
