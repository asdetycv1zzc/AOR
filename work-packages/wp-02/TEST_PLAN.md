# WP-02 Test Plan

1. Table-test every allowed and forbidden Project and ModuleTask transition.
2. Approve Goal only for the exact user, version, digest, and empty unresolved set.
3. Repeat identical commands 100 times and assert one event, one outbox row, one version increment, and identical result.
4. Reuse the idempotency key with changed content and assert conflict without mutation.
5. Race concurrent expected versions and fencing tokens; exactly one current holder succeeds.
6. Inject failure before and after transaction commit and verify atomicity/outbox recovery.
7. Deliver event streams in duplicate, reverse, delayed, and gapped order; compare replay and online projections field by field.
8. Exercise all three failure attempts, dependant freezing, and absence of an automatic retry edge.
9. Supersede Goal/ModuleSpec and reject stale submissions.
10. Validate migration constraints, RLS policy definitions, and expand-migrate-contract metadata.
11. Replay 10,000 events under bounded time and memory in the performance suite.
12. Restart the PostgreSQL inbox between a completed delivery and a duplicate delivery; assert the stored result is returned without invoking the handler. Expire a processing claim and assert only the same digest can reclaim it.
