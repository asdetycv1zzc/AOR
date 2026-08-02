# ADR-0019: Retention, Backup, And Deletion

## Context
Operational recovery, audit obligations, privacy, and legal holds require explicit lifecycle policies.

## Decision
Use SPEC section 44 as the baseline: workflow history 180 days after completion, security audit logs 400 days, release evidence seven years beyond release life, model metadata 180 days, optional prompt content at most 30 days, and tiered backups. Deletion checks legal hold, stops work, removes online copies, invalidates encryption keys, and emits a content-free proof.

## Alternatives
Indefinite retention increases exposure. Immediate untracked backup deletion can violate recovery and legal controls.

## Security Consequences
Deletion and export require scoped approval and immutable audit. Encryption keys and backup access are separated.

## Operational Consequences
Restore and deletion drills verify referential integrity and retention enforcement.

## Migration
Policy may become stricter without data expansion; any relaxation requires approval and a new ADR.

## Status
Accepted
