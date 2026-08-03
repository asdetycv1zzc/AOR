# WP-06 Migration Plan

Introduce capability discovery first, then require attestation on new tasks. Drain existing Windows jobs before enforcing trusted-only scheduling. Configure a dedicated Windows work root and remove inherited environment entries that are not explicitly required. Linux workers must move to rootless Docker, cgroups v2, an approved LSM policy and a versioned seccomp file before accepting leases. Image upgrades use digest allowlists and canary workers. Rollback drains the new pool and restores the previous pinned image/profile pair; it never switches a Linux task to `NONE`.
