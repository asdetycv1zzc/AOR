# Security Policy

## Supported Line

Only the current development line is supported until the first stable release. No repository state may be described as production ready without signed release evidence.

## Reporting

Report vulnerabilities privately to the project security owners. Include the affected commit, reproduction steps, impact, and any observed artifact or audit identifiers. Do not include live credentials.

## Boundaries

- LLM output, generated code, repository content, user input, dependencies, MCP peers, and tool output are untrusted.
- Agent runtimes never receive provider keys, control-plane database credentials, policy write access, or production signing material.
- All tool calls pass through the Tool Broker; all model calls pass through the Model Gateway.
- Linux untrusted execution uses an OCI container with `CONTAINER` isolation. It is a shared-kernel boundary, not a VM.
- Windows execution always reports `NONE` and is limited to explicitly trusted, single-tenant work.

## Incident Handling

Secret exposure, policy bypass, cross-project access, artifact hash mismatch, sandbox escape suspicion, and audit evidence tampering immediately revoke affected leases and preserve structured evidence. Follow the corresponding runbook in `runbooks/`.
