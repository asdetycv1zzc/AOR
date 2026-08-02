# ADR-0004: MCP Version And Compatibility

## Context
Tool and knowledge access needs a stable interoperable protocol without silently adopting release candidates.

## Decision
Pin production MCP to `2025-11-25`. Gate `2026-07-28-RC` behind an experimental flag, separate capability negotiation, and a non-production conformance profile.

## Alternatives
Tracking latest automatically can weaken or change security semantics. A private tool protocol duplicates MCP.

## Security Consequences
Remote peers require HTTPS with OIDC or mTLS. Local servers inherit a minimal environment and never receive provider or control-plane keys.

## Operational Consequences
Tool descriptors and discovery results use deterministic ordering and versioned Schemas.

## Migration
A later baseline needs a superseding ADR, compatibility suite, and product release; no silent switch is allowed.

## Status
Accepted
