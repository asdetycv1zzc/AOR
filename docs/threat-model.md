# AOR Threat Model v1

## Scope

This model covers the control plane, Agent runtimes, Model Gateway, Tool Broker, Repository Service, Knowledge Service, audit pipeline, Linux container workers, Windows native workers, metadata, events, and artifacts. It does not claim that prompts prove correctness or that Linux containers provide a separate kernel.

## Protected Assets

- Goal, Plan, Module, Prompt, and Policy specifications
- source commits, hidden tests, evidence, release manifests, and signing roots
- provider credentials, workload identities, approvals, leases, and nonces
- tenant code, knowledge, personal data, budget, usage, and audit history
- deterministic state and authority to perform state transitions

## Adversaries

User content, repositories, dependencies, package metadata, external pages, MCP/A2A peers, model output, generated code, and Tool output are hostile by default. Executors and expired Agent instances may be malicious. A tenant may attempt enumeration or cross-project access. Trusted services may be misconfigured or operated incorrectly.

## Trust Boundaries

1. User/API boundary authenticates humans and validates every command.
2. Orchestrator boundary is the only business-state writer.
3. Model Gateway boundary owns provider credentials and budget reservation.
4. Tool Broker boundary authorizes all Agent effects and controlled egress.
5. Repository boundary owns writable Git operations and protected merging.
6. Knowledge boundary permits only approved Curator writes.
7. Audit boundary is fresh and separate from Executor workspaces.
8. Linux workers provide shared-kernel OCI isolation; Windows workers provide no execution isolation.

## Threats And Required Controls

| Threat | Control | Verification |
|---|---|---|
| Prompt or indirect injection | source authority labels, bounded context, Schema validation, Broker-only tools | injection corpus |
| Excessive agency | short Capability Leases, deterministic scheduler, approval and commit-time revalidation | denial and revocation tests |
| State forgery | optimistic version, transactional event/outbox write, immutable event history | replay/model tests |
| Replay or duplicate effect | idempotency body digest, Inbox, fencing token, nonce and expiry | 100-duplicate test |
| Goal or evidence substitution | exact version and canonical digest binding | hash mismatch tests |
| Secret exfiltration | Gateway-only keys, deny egress, redaction, no content telemetry | credential canary tests |
| Cross-project access | typed scoped principals, RLS, project-bound object keys | tenant isolation suite |
| Path escape | canonical path, link/reparse checks, scoped Repository writes | traversal corpus |
| SSRF and rebinding | address classification and validation at resolve and every redirect | network corpus |
| Audit manipulation | clean checkout, fixed gate order, blind fresh Auditor, signed evidence | tamper tests |
| Knowledge poisoning | single Curator writer, immutable revision refs, approval | write-denial tests |
| Budget exhaustion | global active limit 8, hard reservation ledger, output and retry caps | concurrency and ledger tests |
| Linux escape | rootless hardened OCI profile, no host socket or broad mount | adversarial container tests |
| Windows overclaim | fixed `NONE`, trusted-only scheduling, prominent disclosure | provider capability tests |
| Supply-chain substitution | locked dependencies, SBOM, provenance, signatures | offline verification |

## Abuse Cases

- An Executor submits a commit touching policy or hidden-test paths.
- A stale lease races a renewed holder and attempts a permanent merge.
- A model emits valid JSON whose fields request a broader action than the task.
- A downloaded artifact redirects to cloud metadata or resolves to a private address.
- A third failed attempt asks the Planner to retry automatically.
- A Windows worker is selected for untrusted production code.

Each case must fail closed and emit a structured security or policy event without including sensitive content.

## Residual Risks

Remote model versions may not be reproducible. Linux containers share the host kernel. Windows native processes can access host resources and may leave untracked children. LLM semantic audit remains probabilistic and never replaces deterministic controls or human release approval.
