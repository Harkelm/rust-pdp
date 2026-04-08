# ADR-003: PDP Deployment Topology (Sidecar vs Remote)

**Status**: Accepted  
**Date**: 2026-04-08  
**Source**: Architecture roundtable RT-26

## Context

Two deployment models: sidecar (PDP in same pod as Kong, 1-3ms latency, co-located
lifecycle) vs remote (PDP as independent service, 3-10ms+ latency, independent
scaling and shared policy state).

## Decision

**Sidecar deployment with a mandatory plugin-side decision cache.**

The plugin-side decision cache is the prerequisite that makes topology secondary.
With a cache (short TTL, 30-60s), most requests never cross the process boundary.
PDP unavailability (including pod restart for policy update) is invisible to
cached traffic.

Key insight from the roundtable: the cache buys deployment topology independence,
not the topology itself. Sidecar is the starting point because it eliminates
network complexity and reduces the distributed consistency problem to single-node.

### Sidecar constraints

- PDP lifecycle is tied to Kong pod lifecycle
- Policy updates must work without pod restart (file watcher + admin API, see
  ADR-004)
- PDP supervision and health checks must be explicit -- a PDP crash inside a Kong
  pod must be detected and surfaced

### Migration path to remote

If independent PDP scaling becomes necessary, the plugin-side cache makes the
transition low-risk. The cache serves traffic during PDP reconnection. The
multi-instance policy consistency model (see prerequisites.md, P0-4) must be
resolved before remote deployment.

## Consequences

- Plugin must implement a decision cache before deployment (not optional)
- PDP health must be wired into Kong's readiness probe
- Multi-instance policy consistency is deferred until remote deployment is needed
- Entity cache coherence across sidecars relies on independent TTL expiry (no
  cross-sidecar invalidation mechanism)
