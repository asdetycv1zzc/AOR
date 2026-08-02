# ADR-0010: Tool Broker And Network Egress

## Context
Tool requests and network destinations are attacker-controlled inputs requiring a single authorization and audit point.

## Decision
All Agent tool calls pass through the Tool Broker. The Broker validates AOP, active Lease, Schema, policy, budget, project state, and scoped capability before execution. Linux and broker egress default to deny; every redirect and resolved address is revalidated.

## Alternatives
Direct SDK or shell access bypasses policy and evidence. DNS-name-only checks permit rebinding and private-address access.

## Security Consequences
Metadata, loopback, private control-plane, and unapproved destinations are denied. Outputs are size-limited, secret-redacted, and untrusted.

## Operational Consequences
Tool descriptors, destination allowlists, decisions, output hashes, and denial metrics must be available.

## Migration
New tools start disabled and need a versioned descriptor, Schema, policy, tests, and owner.

## Status
Accepted
