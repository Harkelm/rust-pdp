# Rust Cedar PDP for Kong API Gateway

External Policy Decision Point (PDP) using Cedar for authorization in a Kong API
gateway deployment. Replaces/augments existing authorization with formally verified,
sub-millisecond policy evaluation.

## Architecture

Kong plugin (Go or Lua) -> HTTP sidecar -> Rust PDP (axum + cedar-policy crate).

The plugin is a thin Policy Enforcement Point (PEP): extract principal ID and
request context, POST to PDP, enforce the decision. The PDP owns all authorization
logic: policy evaluation, entity resolution, schema validation.

## Project Structure

```
projects/rust-pdp/
  docs/
    adr/                    # Architecture Decision Records (6 decisions from RT-26)
      ADR-001 through ADR-006
    prerequisites.md        # 4 P0 blockers that must be resolved before impl
    risk-analysis-and-migration-plan.md  # (BL-160, not yet written)
  knowledge/
    wiki/                   # Compiled research articles (4 articles)
    raw/archived/           # Raw research deposits
    sources.toml            # Tracked sources for scout
  eval-dimensions.toml      # Quality dimensions for /evaluate
  pdp/                      # (BL-153) Rust PDP service
  kong-plugin/              # (BL-154) Kong plugin
  policies/                 # (BL-155) Cedar schema + policy files
  tests/integration/        # (BL-156) Docker-compose test harness
  benchmarks/               # (BL-159) Performance benchmarks
```

Directories below `eval-dimensions.toml` do not exist yet -- they are created by
their respective backlog items.

## Key Decisions (ADRs)

All architecture decisions were made in roundtable RT-26 (9 panelists, 3 rounds).
Read these before implementing:

| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](docs/adr/ADR-001_plugin-language.md) | Go vs Lua plugin | Contested -- needs latency SLA |
| [ADR-002](docs/adr/ADR-002_pdp-protocol.md) | HTTP/JSON for PDP callout | Accepted |
| [ADR-003](docs/adr/ADR-003_deployment-topology.md) | Sidecar + plugin-side cache | Accepted |
| [ADR-004](docs/adr/ADR-004_policy-hot-reload.md) | arc-swap tuple swap + Cache wrapper | Accepted |
| [ADR-005](docs/adr/ADR-005_entity-resolution.md) | Tiered by attribute security class | Accepted |
| [ADR-006](docs/adr/ADR-006_failure-mode.md) | Fail-closed, 503 vs 403 distinction | Accepted |

## Prerequisites (P0 Blockers)

Four findings from the roundtable must be addressed in implementation. See
[prerequisites.md](docs/prerequisites.md) for details:

1. **No FailOpen config toggle** -- 503+Retry-After for PDP unavailability
2. **Mandatory pre-eval schema validation** -- prevent Cedar skip-on-error bypass
3. **PEP/PDP entity trust contract** -- revocable attributes from PDP DB only
4. **Multi-instance policy consistency** -- deferred until remote deployment

## Research

Four wiki articles compiled from research deposits:

- [Cedar Policy Language](knowledge/wiki/cedar-policy-language.md) -- PARC model, evaluation semantics, Rust crate API
- [Kong Plugin Architecture](knowledge/wiki/kong-plugin-architecture.md) -- Phase pipeline, external plugin protocol, Go PDK
- [Rust PDP Service Architecture](knowledge/wiki/rust-pdp-service-architecture.md) -- axum+tonic stack, API design, hot-reload
- [Entitlement Translation](knowledge/wiki/entitlement-translation.md) -- Legacy IAM to Cedar mapping, migration methodology

## Implementation Order

Tasks are in the backlog (`docs/backlog.toml`) with explicit dependencies:

```
BL-152 Architecture RT (done)
  |
  +-- BL-153 Scaffold Rust PDP
  |     +-- BL-157 Hot-reload (arc-swap)
  |     +-- BL-158 Entity translation
  |
  +-- BL-154 Scaffold Kong plugin
  |
  +-- BL-155 Cedar schema design
  |
  +-- BL-156 Integration test (needs 153+154+155)
  |     +-- BL-159 Performance benchmarks
  |
  +-- BL-160 Risk analysis + migration plan (needs 152+156)
```
