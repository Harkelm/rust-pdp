# Rust Cedar PDP for Kong API Gateway

External Policy Decision Point (PDP) using Cedar for authorization in a Kong API
gateway deployment. Replaces/augments existing authorization with formally verified,
sub-millisecond policy evaluation.

## Start Here

If you have 10 minutes, read these three documents in order:

1. **[Risk Analysis and Migration Plan](docs/risk-analysis-and-migration-plan.md)** --
   executive summary, 8 key risks, 4-phase rollout, effort estimates (20-39 eng-days)
2. **[ADR-006: Failure Mode](docs/adr/ADR-006_failure-mode.md)** -- the most important
   security decision (fail-closed, no FailOpen toggle, 503 vs 403 distinction)
3. **[ADR-005: Entity Resolution](docs/adr/ADR-005_entity-resolution.md)** -- the
   tiered entity model that drives the entitlement translation strategy

If you have 30 minutes, also read the remaining ADRs and the
[prerequisites](docs/prerequisites.md). If you want the full deliberation behind
these decisions, see [docs/roundtable/](docs/roundtable/) (9-panelist architecture
review, 3 rounds of debate).

## Architecture

```
                     +-----------+     HTTP/JSON      +-------------+
  Client request --> | Kong GW   | ---- POST -------> | Rust PDP    |
                     | (plugin)  | <--- Allow/Deny -- | (cedar-     |
                     +-----------+                     |  policy 4)  |
                         |                             +-------------+
                         v                                   |
                     Enforce:                           Evaluates:
                     - Allow -> proxy to upstream       - Cedar policies
                     - Deny  -> 403 Forbidden           - Entity hierarchy
                     - Error -> 503 + Retry-After       - Schema validation
```

The plugin is a thin Policy Enforcement Point (PEP): extract principal ID and
request context, POST to PDP, enforce the decision. The PDP owns all authorization
logic: policy evaluation, entity resolution, schema validation.

Two plugin implementations exist (Go and Lua) pending a latency SLA decision.
See [ADR-001](docs/adr/ADR-001_plugin-language.md) for the trade-off analysis.

## Project Structure

```
projects/rust-pdp/
  docs/
    adr/                    # Architecture Decision Records (6 decisions from RT-26)
      ADR-001 through ADR-006
    prerequisites.md        # 4 P0 blockers resolved from roundtable
    risk-analysis-and-migration-plan.md  # Risks, rollout phases, effort estimates
    roundtable/             # Full 9-panelist architecture roundtable (RT-26)
  pdp/                      # Rust PDP service (axum + cedar-policy 4)
    src/                    #   main.rs, handlers.rs, policy.rs, entities.rs, models.rs
    tests/                  #   integration.rs (5 tests), validate_policies.rs
    benches/                #   cedar_eval.rs (Criterion benchmarks)
  kong-plugin-go/           # Kong Go external plugin (ADR-001 Path B)
  kong-plugin-lua/          # Kong Lua plugin (ADR-001 Path A)
  policies/                 # Production Cedar schema + 6 policy files
  tests/integration/        # Docker Compose test harness (Kong + PDP + mock services)
  benchmarks/               # Performance results and load test scripts
  knowledge/
    wiki/                   # Compiled research articles (4 articles)
    raw/archived/           # Raw research deposits
    sources.toml            # Tracked external sources
```

## Running

### Prerequisites

- Rust 1.80+ (tested on 1.92)
- Docker + Docker Compose (for integration tests)
- Go 1.21+ (if building the Go plugin)
- `luarocks install busted` (if running Lua plugin tests)

### Unit Tests

```bash
cd pdp && cargo test
# Runs 16 tests: 10 unit (policy + entity), 5 integration, 1 schema validation
```

### Criterion Benchmarks

```bash
cd pdp && cargo bench
# Generates HTML reports in target/criterion/
# Measures Cedar evaluation latency across policy/entity count matrix
```

### HTTP Load Test

```bash
# Terminal 1: start PDP with test policies
cd pdp && CEDAR_POLICY_DIR=../tests/integration/policies cargo run

# Terminal 2: run load test (1000 requests by default)
cd benchmarks && bash http_load_test.sh
```

### Integration Tests (Docker)

```bash
cd tests/integration
docker compose up -d --build
bash run_tests.sh        # 6 tests: allow, deny, no-auth, timeout, 503, default-deny
bash measure_latency.sh  # Latency distribution with and without PDP
docker compose down
```

## Key Decisions (ADRs)

All architecture decisions were made in roundtable RT-26 (9 panelists, 3 rounds).

| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](docs/adr/ADR-001_plugin-language.md) | Go vs Lua plugin | Contested -- needs latency SLA |
| [ADR-002](docs/adr/ADR-002_pdp-protocol.md) | HTTP/JSON for PDP callout | Accepted |
| [ADR-003](docs/adr/ADR-003_deployment-topology.md) | Sidecar + plugin-side cache | Accepted |
| [ADR-004](docs/adr/ADR-004_policy-hot-reload.md) | arc-swap tuple swap + Cache wrapper | Accepted |
| [ADR-005](docs/adr/ADR-005_entity-resolution.md) | Tiered by attribute security class | Accepted |
| [ADR-006](docs/adr/ADR-006_failure-mode.md) | Fail-closed, 503 vs 403 distinction | Accepted |

## Prerequisites (P0 Blockers)

Four findings from the roundtable. See [prerequisites.md](docs/prerequisites.md):

| ID | Requirement | Status |
|----|-------------|--------|
| P0-1 | No FailOpen config toggle | Addressed in code |
| P0-2 | Pre-eval schema validation | Addressed in code |
| P0-3 | PEP/PDP entity trust contract | Addressed for Lua path; Go path needs API enforcement |
| P0-4 | Multi-instance policy consistency | Deferred (sidecar MVP is single-instance) |

## Research

Four wiki articles compiled from research deposits:

- [Cedar Policy Language](knowledge/wiki/cedar-policy-language.md) -- PARC model, evaluation semantics, Rust crate API
- [Kong Plugin Architecture](knowledge/wiki/kong-plugin-architecture.md) -- Phase pipeline, external plugin protocol, Go PDK
- [Rust PDP Service Architecture](knowledge/wiki/rust-pdp-service-architecture.md) -- axum stack, API design, hot-reload
- [Entitlement Translation](knowledge/wiki/entitlement-translation.md) -- Legacy IAM to Cedar mapping, migration methodology

## Current Status

All prototype tasks complete. See [risk analysis](docs/risk-analysis-and-migration-plan.md)
for what remains before production (Phase 1: 13-24 eng-days).

**What works now:**
- Rust PDP with Cedar policy evaluation, schema validation, hot-reload
- Go and Lua Kong plugins with fail-closed semantics
- Entity resolution from JWT claims (Tier 1)
- Integration test harness (Docker Compose, 6 tests passing)
- Criterion benchmarks (Cedar eval: 5-445us depending on policy count)

**What's not built yet (Phase 1 scope):**
- AuthZen endpoint (`/access/v1/evaluation`) -- deferred; enables engine-agnostic
  external access and PDP engine portability (see ADR-002)
- Tier 2 entity resolution (DB-backed roles/entitlements)
- Decision audit logging
- Admin endpoint authentication
- Shadow mode enforcement toggle
- Policy CI/CD pipeline
- ADR-001 plugin language resolution
