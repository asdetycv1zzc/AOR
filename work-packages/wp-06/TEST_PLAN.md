# WP-06 Test Plan

1. Unit-test platform/isolation/trust/profile fail-closed combinations.
2. Script Docker engine/image/create/start/inspect responses and assert every hardening argument and observed field.
3. Inject engine and container drift and assert cleanup is attempted before failure is returned.
4. Assert Windows reports `NONE`, rejects hostile/isolation-dependent workloads, minimizes environment inheritance and removes its work directory.
5. Test slash and backslash traversal, invalid network modes, credential environment names, concurrent destroy and termination during execution.
6. Cross-compile the package for Windows amd64.
7. In the release environment, run live rootless-Docker escape, network-denial, mount, resource-exhaustion, process-tree cleanup and encrypted-snapshot tests. Those results belong in WP-15 release evidence, not in unit fixtures.
