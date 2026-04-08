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
- Batch authorization endpoint (`/v1/batch_is_authorized`) with rayon parallel eval
- Go and Lua Kong plugins with fail-closed semantics
- Entity resolution from JWT claims (Tier 1)
- Integration test harness (Docker Compose, 6 tests passing)
- Criterion benchmarks (Cedar eval: 5-445us depending on policy count)
- Concurrent HTTP throughput benchmarks (oha-based, configurable concurrency)
- Go vs Lua plugin comparison infrastructure (Docker stacks, automated scripts)
- Cache effectiveness and stampede simulation benchmarks

**What's not built yet (Phase 1 scope):**
- AuthZen endpoint (`/access/v1/evaluation`) -- deferred; enables engine-agnostic
  external access and PDP engine portability (see ADR-002)
- Tier 2 entity resolution (DB-backed roles/entitlements)
- Decision audit logging
- Admin endpoint authentication
- Shadow mode enforcement toggle
- Policy CI/CD pipeline
- ADR-001 plugin language resolution

## Performance Baselines

All numbers measured on i7-14700KF (20c/28t), 32GB RAM, Rust 1.92, Cedar 4.9.1.
See [benchmarks/RESULTS.md](benchmarks/RESULTS.md) for detailed results and methodology.

### Cedar Evaluation (In-Process, Criterion)

| Scenario | Policies | Mean | What it exercises |
|----------|----------|------|-------------------|
| Trivial permit (10 policies, flat) | 10 | 5.2 us | Equality check baseline |
| Trivial permit (100 policies, flat) | 100 | 45 us | Linear scaling validation |
| Trivial permit (1000 policies, flat) | 1000 | 445 us | Upper bound, simple policies |
| **Realistic: admin-read** | 10 prod | 9.6 us | `in` membership traversal (RBAC) |
| **Realistic: viewer-delete-deny** | 10 prod | 6.9 us | Full policy scan, no match |
| **Realistic: suspended-admin-deny** | 10 prod | 9.4 us | Forbid override |
| **Realistic: data-scope-allow** | 10 prod | 9.1 us | `.contains()` set membership |
| **Realistic: cross-org-deny** | 10 prod | 13.5 us | Attribute mismatch |
| **Realistic: multi-role-write** | 10 prod | 15.6 us | Multiple `in` checks |
| **Realistic + 100 noise** | 110 | 93 us | Complex predicates at scale |
| **Realistic + 500 noise** | 510 | 423 us | Complex predicates at scale |
| **Realistic + 1000 noise** | 1010 | 835 us | Complex predicates at scale |
| **Hierarchy depth 5** | 10 | 5.5 us | `in` traversal, 5-level DAG |
| **Hierarchy depth 10** | 10 | 5.5 us | `in` traversal, 10-level DAG |
| **Hierarchy depth 15** | 10 | 8.4 us | `in` traversal, 15-level DAG |
| **Hierarchy depth 20** | 10 | 8.6 us | `in` traversal, 20-level DAG |

### HTTP Round-Trip (PDP Server)

| Metric | Sequential (curl) | Concurrent (oha, c=100) |
|--------|-------------------|-------------------------|
| P50 | 0.225 ms | 0.910 ms |
| P95 | 0.343 ms | 2.837 ms |
| P99 | 0.425 ms | 4.493 ms |
| Max RPS | N/A (sequential) | 87,189 (Allow), 220,567 (Deny) |

Deny requests are faster because they short-circuit after finding no matching
permit (6.9us eval) vs Allow which must evaluate matching policies (9.6us+).
At concurrency 500, Allow sustains 111K RPS (p99=18ms), Deny sustains 222K RPS
(p99=8ms). The 5ms p99 budget is met up to concurrency ~100 for Allow requests.

### Capacity Planning

| Metric | Value | Conditions |
|--------|-------|------------|
| Cedar eval per-policy cost | ~4.5 us/policy (trivial), ~0.8 us/policy (realistic) | Linear scaling |
| Policy count for 1ms Cedar budget | ~220 (trivial), ~1200 (realistic) | Interpolated |
| HTTP overhead (localhost) | ~220 us | JSON ser/de + tokio dispatch |
| Memory per policy | ~2 KB/policy | Measured at 10K policies |
| Memory per entity | ~555 bytes/entity | Measured at 10K entities |
| Schema memory | ~18 KB | Production schema (ApiGateway) |
| Entity hierarchy depth budget | 20 levels = 8.6 us | `in` traversal, linear chain |
| Batch speedup vs sequential | 4.5x (100 decisions) | rayon parallel eval |
| Batch peak throughput | 192K decisions/sec | batch_100 x concurrency 50 |

### Go vs Lua Plugin Comparison

Measured via Docker stacks (Kong 3.9, production policies, cache disabled).

| Concurrency | Metric | Lua Plugin | Go Plugin | Go/Lua Ratio |
|-------------|--------|------------|-----------|--------------|
| 1 | p50 | 0.026 ms | 0.195 ms | 7.5x slower |
| 1 | RPS | 27,305 | 4,815 | 0.18x |
| 10 | p50 | 0.093 ms | 0.503 ms | 5.4x slower |
| 10 | RPS | 86,704 | 13,797 | 0.16x |
| 50 | p50 | 0.236 ms | 3.959 ms | 16.8x slower |
| 50 | RPS | 149,202 | 7,103 | 0.05x |
| 100 | p50 | 0.439 ms | 15.747 ms | 35.9x slower |
| 100 | RPS | 141,977 | 5,234 | 0.04x |

**Key finding**: The Go external plugin IPC overhead is far worse than the
literature estimate (0.3-0.5ms). At concurrency 50, Go plugin adds ~3.7ms p50
vs Lua's 0.1ms -- a 37x overhead, not 3-5x. At concurrency 100, Go throughput
collapses to 5K RPS vs Lua's 142K RPS (96% reduction).

**Direct PDP** (bypass Kong) sustains 425K RPS at concurrency 100, confirming
that Kong + plugin layer is the bottleneck, not Cedar evaluation.

**Implication for ADR-001**: The Go external plugin IPC tax is not "0.3-0.5ms
fixed" -- it grows dramatically with concurrency. Lua is the correct choice for
latency-sensitive deployments. Go is viable only with aggressive decision caching
(90%+ hit rate) to avoid the IPC path. Run `benchmarks/cache_effectiveness.sh`
for cache hit rate measurement.

### Known Scaling Limits

- **tokio blocking pool**: Default 512 threads. Batch endpoint uses rayon instead
  of `spawn_blocking` per sub-request to avoid saturation.
- **Cedar evaluation**: O(n) in policy count. 1000 policies = ~445us (trivial),
  ~835us (realistic with RBAC/ABAC). Realistic policies cost ~1.9x trivial.
- **Entity hierarchy**: depth 1-10 = ~5.5us, depth 15-20 = ~8.5us. Sub-linear
  scaling -- Cedar's entity lookup is hash-based, not scan-based.
- **Hot-reload under load**: arc-swap reload adds ~4ms to p99 (+102%) at
  concurrency 100. Median reload completes in 15-21ms. No dropped requests.
- **Memory at scale**: 10K policies = 19 MB, 10K entities = 5.3 MB.
- **Sidecar cache**: No cross-instance invalidation. Stale window = TTL (30-60s).
  No TTL jitter (stampede risk). See `benchmarks/stampede_sim.sh`.
- **Batch concurrency ceiling**: batch_100 x concurrency_50 = p99 of 51ms.
  Batch_10 x concurrency_50 = p99 of 6ms. Stay below batch_50 for <10ms p99.

### Reproduction

Prerequisites: Rust 1.80+, Docker + Compose, `cargo install oha`

```bash
# Criterion in-process benchmarks (realistic policies, hierarchy, scaling)
cd pdp && cargo bench

# Memory scaling measurement
cd pdp && cargo run --example memory_scaling --release

# Concurrent HTTP throughput (requires PDP running with production policies)
cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release  # terminal 1
cd benchmarks && bash concurrent_throughput.sh               # terminal 2

# Hot-reload latency spike
cd benchmarks && bash reload_spike.sh

# Go vs Lua plugin comparison (Docker, ~10 min)
cd benchmarks && bash go_vs_lua.sh

# Batch endpoint stress test (requires PDP running)
cd benchmarks && bash batch_stress.sh

# Cache effectiveness across TTL values (Docker, ~20 min)
cd benchmarks && bash cache_effectiveness.sh

# Cache stampede simulation (Docker, ~5 min)
cd benchmarks && bash stampede_sim.sh
```

Hardware note: Run benchmarks with no background load. On Linux, use
`cpupower frequency-set -g performance` to disable CPU frequency scaling for
consistent results.
