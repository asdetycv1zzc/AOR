# WP-06 Sandbox Module Specification

- Task ID: `WP-06`
- Phase: `3`
- Dependencies: `WP-03`, `WP-05`
- Risk: `CRITICAL`

## Purpose

Expose one lifecycle interface while preserving the non-equivalent security semantics of Linux containers and Windows native processes.

## Responsibilities

- Validate `LINUX+CONTAINER` and `WINDOWS+NONE` as the only platform combinations.
- Require pinned OCI image digests and hardened container controls on Linux.
- Report `NONE` continuously for Windows and reject untrusted production or hidden-test workloads.
- Enforce lifecycle, export path, resource and attestation contracts.

## Non-responsibilities

- VM, MicroVM, Hyper-V, Windows Container or AppContainer isolation.
- Tool authorization and business-state transitions.

## Allowed paths

`internal/sandbox/`, `sandbox/`, `work-packages/wp-06/`, `conformance/requirements.yaml`.

## Acceptance criteria

1. Invalid platform/isolation combinations fail before backend execution.
2. Linux requires digest-pinned images, non-root, read-only rootfs, dropped capabilities, seccomp and denied host namespaces/socket.
3. Windows always reports `NONE` and rejects untrusted production and secrecy-dependent audit work.
4. Export rejects traversal and malformed artifact evidence; destroy is idempotent under concurrency.
5. The Linux Docker backend probes the engine and inspects the created container before returning a handle.
6. The Windows backend runs only on Windows, exposes no isolation claim, filters inherited environment variables and owns a dedicated work directory.
