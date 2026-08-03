# WP-08 Migration Plan

Deploy raw Plan/Module validation first, then enable immutable artifact writes, and finally route publication through the atomic multi-aggregate command. Drain legacy planners before enabling the new path so a project cannot mix publication semantics. Existing drafts require a verified content hash and version before import; mutable drafts are copied into a new immutable version. Rollback stops new planning and drains active runs, but never deletes artifacts, approvals or emitted events.
