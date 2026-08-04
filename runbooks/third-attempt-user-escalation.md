# Third Attempt User Escalation

Severity: SEV-2. Alert: `AORThirdAttemptFailure`.

Symptoms: a ModuleTask fails its third submission or audit attempt. Containment: transition it to `BLOCKED_USER_DECISION`, freeze dependent scheduling, and prevent automatic replanning or retry.

Diagnosis: inspect the immutable three submission manifests, deterministic gate results, audit findings, module and goal references, and the latest trace. Do not pass executor explanations to a blind auditor.

Recovery: notify the authorized user with the complete evidence bundle. Resume only through an explicit decision command bound to the current task and spec versions.

Verification: confirm no fourth attempt or automatic planner invocation exists and that all dependencies remain frozen until the decision is persisted.

Evidence: save the failure bundle, notification receipt, decision approval, and state/event digests. Retrospective: review acceptance criteria and retry classification.
