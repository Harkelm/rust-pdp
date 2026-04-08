# ADR-002: PDP Communication Protocol (HTTP vs gRPC)

**Status**: Accepted  
**Date**: 2026-04-08  
**Source**: Architecture roundtable RT-26

## Context

The Kong plugin communicates with the Rust PDP over localhost (sidecar deployment).
Two protocol options: HTTP/JSON (simpler, curl-debuggable) vs gRPC/protobuf (lower
serialization overhead, generated types, streaming).

For a typical Cedar PARC request (principal string, action string, resource string,
context record), the serialization difference is minimal (~50-200 bytes). For
entity-heavy requests with 5-10 relationships, gRPC's binary encoding has a
measurable advantage.

## Decision

**Start with HTTP/JSON.** gRPC adds proto compilation, generated stubs, and binary
framing complexity for marginal latency gain on a localhost call.

Rationale:
- Sidecar deployment means localhost networking -- serialization overhead is noise
- HTTP/JSON is curl-debuggable, simplifying development and on-call diagnosis
- The PDP exposes a Cedar-native API (`/v1/is_authorized`) for the Kong plugin
  (internal). An AuthZen-compatible endpoint (`/access/v1/evaluation`) is planned
  for external consumers but deferred until Phase 1 core is complete
- Migration to gRPC is a transport swap within the Go plugin abstraction if
  profiling later shows serialization as the bottleneck

The AuthZen endpoint on the PDP's public API would enable engine-swapping (Cedar to
OPA) and PEP-swapping (Kong to another gateway) without changing the other side.
This is deferred: the Kong plugin is the only consumer in Phase 1, and Cedar-native
is sufficient. AuthZen becomes valuable when external consumers or engine portability
are needed.

## Consequences

- Kong plugin calls Cedar-native endpoint (`/v1/is_authorized`), not AuthZen
- gRPC endpoint should not be implemented until profiling identifies serialization
  as an actual bottleneck
- AuthZen endpoint (`/access/v1/evaluation`) is deferred to post-Phase 1. It will
  be needed when external consumers require engine-agnostic authorization, or when
  PDP engine portability (Cedar to OPA) is desired
