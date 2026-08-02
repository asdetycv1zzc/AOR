# ADR-0011: Linux OCI Container Sandbox

## Context
Production untrusted code needs enforceable Linux isolation while the product explicitly excludes VM backends.

## Decision
Use a fresh OCI-compatible container for each Executor or Auditor with a digest-pinned image, non-root user namespace, read-only root, scoped mounts, seccomp, capability drop, resource limits, PID limits, and deny-by-default network.

## Alternatives
Host processes are insufficient for untrusted production code. VM and microVM backends are outside the product scope.

## Security Consequences
Containers share the host kernel and are not suitable for workloads designed to exploit the kernel. Host sockets, privileged mode, and broad mounts are forbidden.

## Operational Consequences
Kernel/runtime patching, capability probes, image signing, cleanup attestation, and adversarial tests are required.

## Migration
Sandbox image and runtime profiles are independently versioned; old task leases cannot silently change profile.

## Status
Accepted
