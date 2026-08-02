# WP-02 Operations

Monitor command conflict rate, transaction latency, outbox lag, projection gap depth, duplicate delivery, replay failures, blocked modules, and attempt-series creation. Alert on any event-version conflict, unexplained projection drift, or outbox row older than the delivery SLO.

Outbox publishers claim rows with bounded leases and mark publication only after broker acknowledgement. Replay operates from immutable events into a new projection and compares results before cutover. Dead letters are never automatically deleted.
