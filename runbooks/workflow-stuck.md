# Workflow Stuck

Severity: SEV-2, SEV-1 if the queue is global. Alert: `AORWorkflowStuck`.

Symptoms: a workflow heartbeat or state version does not advance within its policy window. Containment: pause scheduling for the affected project and do not manually mutate state tables.

Diagnosis: inspect workflow history, activity result records, lease expiry, outbox entries, and the latest trace. Check whether the worker is waiting on a dependency, budget reservation, or provider reconciliation.

Recovery: allow the durable workflow to retry a retryable activity, or issue the documented user decision command for a blocked third attempt. Restarting a stateless worker is safe after confirming the workflow idempotency key.

Verification: replay the history, compare online projections, verify one-and-only-one side effect, and confirm the task state transition is legal.

Evidence: retain workflow ID, history digest, state snapshots, lease and budget records, and operator actions. Retrospective: identify the missing timeout or recovery signal.
