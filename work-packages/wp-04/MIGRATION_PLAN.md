# WP-04 Migration Plan

Budget accounts and reservations are additive tables with immutable usage records. Expand existing metadata first, deploy gateway readers, then enable settlement writers. No destructive cleanup occurs until all old workers are drained.
