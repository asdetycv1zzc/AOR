# WP-06 Interfaces

`SandboxProvider` implements `Create`, `Exec`, `Export`, `Snapshot`, `Terminate` and `Destroy`. `Backend` is the runtime-specific boundary and returns observed runtime attestation from `Create`; the provider rejects incomplete Linux hardening evidence. `DockerBackend` is the Linux OCI implementation and `WindowsNativeBackend` is the Windows `NONE` implementation. `BlobStore` receives streaming export and encrypted-snapshot producers, so large data is not buffered by the provider. `SandboxHandle` and `SnapshotRef` always state the actual isolation level.
