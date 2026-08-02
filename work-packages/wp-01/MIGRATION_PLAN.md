# WP-01 Migration Plan

Version `1.x` permits optional additive fields. Removed fields, newly required fields, or changed meaning require `2.0` and an adjacent-major compatibility window. Converters are pure functions with explicit loss reports.

Rollback restores the previous contracts and Go validators before any dependent persistence migration. Persisted messages retain their declared Schema and AOP versions.
