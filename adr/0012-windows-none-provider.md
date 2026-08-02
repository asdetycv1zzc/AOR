# ADR-0012: Windows Native Execution With No Isolation

## Context
Windows support is required for trusted tasks, but the product forbids Windows containers, AppContainer, Hyper-V, VMs, or similar isolation backends.

## Decision
Run tracked native processes in a dedicated working directory and always report `platform=WINDOWS`, `isolationLevel=NONE`, and network enforcement unavailable. Reject untrusted production, hostile multi-tenant, hidden-test-confidential, or isolation-requiring work.

## Alternatives
Describing directory separation as a sandbox is misleading. Adding an isolation backend contradicts the product scope.

## Security Consequences
The provider cannot prevent host file, credential, process, or network access and cannot guarantee cleanup of untracked children.

## Operational Consequences
API, CLI, logs, scheduling, and evidence prominently disclose `NONE`; explicit immutable risk acceptance is required where policy permits.

## Migration
Any future isolation backend requires a major product-scope change and a superseding ADR.

## Status
Accepted
