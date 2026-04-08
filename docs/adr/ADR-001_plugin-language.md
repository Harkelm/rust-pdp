# ADR-001: Kong Plugin Language (Go vs Lua)

**Status**: Contested  
**Date**: 2026-04-08  
**Source**: Architecture roundtable RT-26, 9 panelists, 3 deliberation rounds

## Context

Kong external plugins (Go, Python, JS) run as separate processes communicating
over Unix domain sockets. The IPC overhead is a fixed cost: benchmarks show -25%
throughput and +0.34ms latency for an empty Go plugin. Lua plugins run in-process
with zero IPC overhead but lack type safety, testing ecosystem, and JWT parsing
libraries.

Cedar policy evaluation takes 0.1-1ms. The Go IPC floor cost (0.3-0.5ms) is
30-500% of the evaluation cost itself.

## Decision

**State the latency budget explicitly, then derive the language choice.**

Two architecturally valid paths exist:

### Path A: Thin Lua shim + thick Rust PDP (latency-sensitive)

The plugin is a ~40-60 line HTTP client. It extracts principal ID and request
context from the Kong PDK, POSTs to the PDP, enforces the decision. All entity
resolution, JWT decoding, hierarchy construction lives in the Rust PDP.

Advantages:
- Zero IPC overhead
- Resolves the entity trust boundary structurally (plugin sends only principal ID
  + method + path, no entities array injection surface)
- Clean PEP/PDP separation of concerns

Disadvantages:
- Lua tooling is weaker (debugging, testing, type safety)
- Kong's sandboxed Lua environment has limitations
- Discipline required to keep it as a shim

### Path B: Go plugin (development-velocity-first)

The plugin uses Go's type system, HTTP client, JSON handling, and test tooling.
Entity assembly logic may live in the plugin or the PDP.

Advantages:
- Type safety, proper test story, mature dependency ecosystem
- Go PDK is the most mature external plugin option

Disadvantages:
- Fixed 0.3-0.5ms IPC floor cost, irrecoverable
- Migration to Lua later is a full plugin rewrite, not a transport swap

### Required prerequisite

The architecture spec must include a p99 latency SLA for the authorization path.
If the SLA cannot accommodate the IPC floor cost, Path A is required. If
development velocity is the primary constraint and the SLA is comfortable (e.g.,
>10ms), Path B is acceptable.

## Consequences

- Downstream implementation (scaffold task) must wait for latency SLA definition
- If Path A is chosen, the entity trust boundary (ADR-005) is resolved
  structurally -- the plugin cannot inject entity data
- If Path B is chosen, the PDP API must enforce entity trust boundaries
  independently (see prerequisites.md, P0-3)
