# WP-06 Threat Model

| Threat | Control |
|---|---|
| Platform capability overclaim | Exact platform/isolation validation and explicit attestation |
| Container escape precondition | No privileged mode, host namespaces, host network, devices or runtime socket |
| Credential mount | Operator-owned source-root allowlist, read-only input targets and runtime-socket rejection |
| Windows hostile workload | Scheduler validation rejects untrusted production and secrecy-dependent tasks |
| Artifact traversal | OS-independent canonical relative paths, streaming archives and no symlink export |
| Engine drift | Rootless/cgroups-v2/LSM probe plus post-create container inspection |
| Concurrent cleanup | Per-sandbox control serialization and fail-closed lifecycle state |
| Windows credential inheritance | Empty-by-default environment with credential-like variable names rejected |

Linux containers still share the host kernel. Windows native processes can access the host and may create untracked descendants; neither work-directory separation nor process tracking changes `isolationLevel=NONE`.
