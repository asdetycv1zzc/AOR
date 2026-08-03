# WP-08 Test Plan

1. Run 100 single-agent rounds and assert the project remains `GOAL_NEGOTIATING` with no Plan.
2. Assert the dual-agent order is Proposer, Challenger, Proposer with distinct Challenger identity and immutable artifacts.
3. Reject unresolved GoalSpec approval and malformed approval bindings.
4. Retry negotiations, approvals and plan publication with the same idempotency key and assert no new side effect.
5. Reject cycles, unknown modules, open decisions, duplicate interfaces and overlapping path ownership.
6. Assert ModuleSpec agents cannot change plan-owned paths, dependencies, interfaces, platform or acceptance criteria.
7. Inject event-store failure before commit and assert neither project nor any task changes.
8. Change an approved goal and assert only listed impacted tasks become `SUPERSEDED`.
9. Re-plan after a goal change and assert an unchanged task is retained while an impacted module receives new task and ModuleSpec versions.
