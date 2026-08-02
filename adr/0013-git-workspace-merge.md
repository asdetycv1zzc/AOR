# ADR-0013: Git Workspace, Commit, And Merge Queue

## Context
Executors need scoped source changes without direct write access to protected repositories or the ability to rewrite accepted submissions.

## Decision
Repository Service owns bare repositories, isolated worktrees, branches, path validation, commits, signatures, diff generation, and merge queue admission. Every attempt refers to immutable base and head commits.

## Alternatives
Giving Executor credentials to the primary repository breaks scope and merge control. Mutable patch uploads weaken provenance.

## Security Consequences
Disable hooks, unsafe filters, submodule side effects, and untrusted Git configuration. Normalize and resolve paths before enforcing ownership.

## Operational Consequences
Worktree cleanup, object integrity, merge contention, signature verification, and queue latency require monitoring.

## Migration
Repository metadata is additive; changing Git policy requires re-auditing pending submissions.

## Status
Accepted
