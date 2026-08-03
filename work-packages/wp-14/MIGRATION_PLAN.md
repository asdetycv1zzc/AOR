# Migration Plan

Deploy expand-only database migrations first, enable dual-read compatibility, run backup/restore evidence, and perform destructive cleanup only after all old workers retire.
