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
- The PDP exposes two API surfaces: Cedar-native (`/v1/is_authorized`) for the
  Kong plugin (internal), AuthZen (`/access/v1/evaluation`) for external consumers
- Migration to gRPC is a transport swap within the Go plugin abstraction if
  profiling later shows serialization as the bottleneck

The AuthZen endpoint on the PDP's public API enables engine-swapping (Cedar to OPA)
and PEP-swapping (Kong to another gateway) without changing the other side.

## Consequences

- Kong plugin calls Cedar-native endpoint (`/v1/is_authorized`), not AuthZen
- gRPC endpoint should not be implemented until profiling identifies serialization
  as an actual bottleneck
- AuthZen endpoint is implemented for external/future consumers, not for the Kong
  plugin
