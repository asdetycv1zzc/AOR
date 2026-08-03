# WP-08 Operations

Alert on artifact hash mismatch, immutable-key conflict, role mismatch, approval rejection, invalid DAG/ownership, and atomic publication failure. Orphan artifacts created before a rejected state command are safe to retain and can be reclaimed only by the retention workflow after proving no projection/event reference exists. Operators must not edit a GoalSpec or PlanSpec projection; correction creates a new version and compensating event.

Track negotiation rounds, unresolved items, challenge severity, planner failures, module count, DAG depth and publication latency. High module count and repeated ownership failures are planning-quality signals, not reasons to auto-approve or silently rewrite the plan.
