# Sandbox Escape Suspected

Severity: SEV-1. Alert: `AORSandboxSecurityEvent` or unexpected host access.

Symptoms: a container reports forbidden mounts, privilege changes, host process access, or unexpected network traffic. Containment: isolate the worker host, stop scheduling untrusted work, revoke leases, and preserve the container and host evidence. Do not destroy the suspected container until capture is complete.

Diagnosis: record the immutable image digest, runtime attestation, container inspect data, cgroup and security-policy status, process tree, network flow, and relevant traces. Do not collect secret contents.

Recovery: terminate and destroy the workload after forensic approval, rotate affected credentials, rebuild from a signed image, and require sandbox preflight before resuming.

Verification: rerun adversarial mount, network, capability, seccomp, and process-isolation tests; confirm the worker reports `CONTAINER` and no host socket is exposed.

Evidence: encrypt the snapshot, hash all evidence, record break-glass approval and chain of custody. Retrospective: file a security incident and update the corpus with a regression case.
