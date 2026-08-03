# WP-06 Operations

Linux workers require a rootless Docker Engine using cgroups v2, the configured OCI runtime, an explicit seccomp file and an active AppArmor or SELinux policy. Images must already exist locally by exact `sha256:` ID; the backend uses `--pull=never`. Direct sandbox networking is `DENY_ALL`; an `ALLOWLIST` request is rejected until a separately attested network controller exists.

Windows workers require a dedicated local work root that is not a volume root or symlink. They are admitted only under the `NONE` scheduling rules. Snapshot storage must implement encrypted streaming; export/snapshot calls fail closed when no blob store is configured.

Alert on engine or container attestation drift, forbidden Windows scheduling, cleanup failure, residual processes and image mismatch. Quarantine a worker after cleanup or attestation failure and reconcile the container/process inventory before returning it to service. Never downgrade isolation during incident recovery.
