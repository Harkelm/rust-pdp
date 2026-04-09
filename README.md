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

Two plugin implementations exist (Go and Lua). Benchmark data resolved this in
favor of Lua -- Go IPC overhead collapses throughput 96% at concurrency 100.
See [ADR-001](docs/adr/ADR-001_plugin-language.md) for the trade-off analysis and
measured data.

## Project Structure

```
projects/rust-pdp/
  docs/
    adr/                    # Architecture Decision Records (6 decisions from RT-26)
      ADR-001 through ADR-006
    prerequisites.md        # 4 P0 blockers resolved from roundtable
    risk-analysis-and-migration-plan.md  # Risks, rollout phases, effort estimates
    agent-reviews/          # Independent code reviews (tech-lead, field-agent)
    roundtable/             # Full 9-panelist architecture roundtable (RT-26)
  pdp/                      # Rust PDP service (axum + cedar-policy 4)
    src/                    #   main.rs, handlers.rs, avp.rs, policy.rs, entities.rs, models.rs
    tests/                  #   integration, security, concurrency, policy_coverage, avp_compat, etc. (142 tests)
    benches/                #   cedar_eval.rs, hierarchy_depth.rs, avp_format_overhead.rs (Criterion benchmarks)
    examples/               #   memory_scaling.rs (heap measurement)
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

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CEDAR_POLICY_DIR` | `./policies` | Path to directory containing `.cedar` and `.cedarschema` files |
| `PDP_PORT` | `8180` | HTTP server listen port |
| `PDP_ADMIN_TOKEN` | _(unset)_ | Bearer token for `/admin/reload`. If unset, admin is unrestricted (dev mode) with startup warning |
| `RUST_LOG` | `cedar_pdp=info` | Tracing filter directive |

## API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/is_authorized` | POST | None | Single authorization decision (native format) |
| `/v1/batch_is_authorized` | POST | None | Batch authorization, max 100 (native format) |
| `/avp/is-authorized` | POST | None | Single authorization (AVP wire format) |
| `/avp/batch-is-authorized` | POST | None | Batch authorization, max 30 (AVP wire format) |
| `/v1/policy-info` | GET | None | Policy count, last reload time, schema hash |
| `/admin/reload` | POST | Bearer `PDP_ADMIN_TOKEN` | Force policy reload from disk |
| `/healthz` | GET | None | Liveness probe (always 200 if process is up) |
| `/readyz` | GET | None | Readiness probe (200 when policies loaded) |
| `/health` | GET | None | Backward-compat alias for `/readyz` |

All responses include an `X-Request-Id` header (propagated from request or generated UUID v4).

### AVP-Compatible Endpoints

The `/avp/*` endpoints accept the same JSON wire format as Amazon Verified Permissions,
allowing clients to swap between the self-hosted PDP and AVP without code changes.

Key differences from native endpoints:
- Entity references use `{ "entityType": "T", "entityId": "id" }` instead of Cedar UID strings
- Context uses typed value wrappers: `{ "String": "foo" }`, `{ "Boolean": true }`, `{ "Long": 42 }`, `{ "Set": [...] }`, `{ "Record": {...} }`, `{ "EntityIdentifier": {...} }`
- Entity hierarchy provided as explicit `entities.entityList` (not derived from JWT claims)
- Decision is uppercase `ALLOW`/`DENY` (not `Allow`/`Deny`)
- Policies returned as `determiningPolicies: [{ policyId }]` (not `diagnostics.reason`)
- Batch endpoint enforces same-principal-or-same-resource homogeneity constraint (30-item limit)
- `policyStoreId` is accepted but ignored (single-store deployment)

See `docs/avp-comparison-and-api-compatibility.md` for the full comparison analysis.

## Running

### Prerequisites

- Rust 1.80+ (tested on 1.92)
- Docker + Docker Compose (for integration tests)
- Go 1.26+ (if building the Go plugin; go.mod declares 1.26.2)
- `luarocks install busted` (if running Lua plugin tests)

### Unit Tests

```bash
cd pdp && cargo test
# Runs 149 tests: 34 unit, 16 avp_compat, 7 avp_stress, 85 integration/security/policy, 7 stress
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
# Optional env vars: PDP_PORT=8181, PDP_ADMIN_TOKEN=secret

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
| [ADR-001](docs/adr/ADR-001_plugin-language.md) | Go vs Lua plugin | Resolved -- Lua (benchmark data) |
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
- AVP-compatible endpoints (`/avp/is-authorized`, `/avp/batch-is-authorized`) matching Amazon Verified Permissions wire format
- Go and Lua Kong plugins with fail-closed semantics
- Entity resolution from JWT claims (Tier 1)
- Integration test harness (Docker Compose, 6 tests passing)
- Criterion benchmarks (Cedar eval: 5-445us depending on policy count)
- Concurrent HTTP throughput benchmarks (oha-based, configurable concurrency)
- Go vs Lua plugin comparison infrastructure (Docker stacks, automated scripts)
- Cache effectiveness and stampede simulation benchmarks
- Admin endpoint authentication (`PDP_ADMIN_TOKEN` Bearer token)
- Graceful shutdown (SIGTERM/SIGINT drain with in-flight request completion)
- Kubernetes-style health probes (`/healthz` liveness, `/readyz` readiness)
- X-Request-Id middleware (propagate or generate UUID v4 for log correlation)
- Configurable port via `PDP_PORT` env var (default 8180)
- Non-root container user in production Dockerfile

### AVP Compatibility Status

The authorization hot path is fully implemented and stress-tested. Clients can
use `/avp/is-authorized` and `/avp/batch-is-authorized` with the same JSON
request/response format as Amazon Verified Permissions. No code changes needed
to swap between this PDP and AVP for authorization decisions.

**Implemented (149 tests passing, stress-tested to c=2000):**
- `IsAuthorized` -- single authorization with AVP wire format
- `BatchIsAuthorized` -- batch authorization (30-item limit, homogeneity constraint)
- AVP typed value wrappers (String, Boolean, Long, Set, Record, EntityIdentifier)
- Explicit entity hierarchy via `entities.entityList`
- `policyStoreId` accepted (ignored in single-store deployment)
- Fail-closed: malformed requests always produce DENY with error, never 500
- Format overhead: +9 us constant per request (~42% on full path with 10 production policies; proportionally less with more policies)

**Not implemented -- requires enterprise infrastructure decisions:**

| AVP Feature | What It Does | Why It Requires Infrastructure |
|-------------|-------------|-------------------------------|
| `IsAuthorizedWithToken` | Validates JWT/OIDC tokens before authorization | Requires identity provider config (Cognito, Okta, etc.) and token validation infrastructure |
| `BatchIsAuthorizedWithToken` | Batch version of token-based auth | Same as above |
| Multi-store routing | `policyStoreId` maps to tenant-specific policy sets | Requires multi-tenant architecture decision: namespace isolation, policy storage backend, routing layer |
| Policy CRUD API | Create/Update/Delete/List policies via API (16 AVP operations) | Requires policy storage backend (DB or git), versioning strategy, access control on who can modify policies |
| Policy templates API | Create/link/manage parameterized policy templates | Requires template storage + runtime linking infrastructure |
| Identity sources | Connect to Cognito user pools or OIDC providers | Requires IAM integration, token refresh, user pool sync |
| Schema management API | CRUD operations on Cedar schema | Requires schema versioning, migration strategy, validation pipeline |
| Decision audit logging | Durable log of every authorization decision | Requires logging infrastructure (CloudTrail equivalent), retention policy, query interface |

These features are the management plane -- they surround the authorization engine
but don't affect how policies are evaluated. The Cedar evaluation engine, policy
format, and entity model are identical whether managed by AVP or by this PDP.
The delta is in how policies get into the system and how decisions get logged out.

**Self-contained engineering work (no infrastructure dependency):**
- AuthZen endpoint (`/access/v1/evaluation`) -- open standard alternative to AVP format
- Shadow mode enforcement toggle -- log decisions without enforcing, for rollout
- Tier 2 entity resolution (DB-backed roles/entitlements beyond JWT claims)
- Policy CI/CD pipeline (lint, test, deploy `.cedar` files)


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

### AVP Format Overhead (In-Process, Criterion)

| Scenario | Native | AVP | Overhead |
|----------|--------|-----|----------|
| Parse only (no eval) | 9.4 us | 18.1 us | +93% |
| Full path (parse + eval) | 20.7 us | 29.3 us | +42% |
| Response serialization | 52 ns | 53 ns | ~0% |
| Batch 10 (sequential eval) | 205 us | 298 us | +45% |
| Batch 30 (sequential eval) | 618 us | 900 us | +46% |

The AVP parsing overhead (~9 us constant) comes from typed value wrapper
deserialization and explicit entity construction. This is a fixed cost per
request independent of policy count or Cedar evaluation time. At production
policy counts (10+ policies, 10+ us eval), the overhead is <50% of total
request time and shrinks proportionally as policy complexity grows.

### AVP Stress Test Results (HTTP, localhost)

| Test | Concurrency | Requests | Result |
|------|-------------|----------|--------|
| Single authz correctness | 500 | 500 | 100% correct (250 ALLOW, 250 DENY) |
| Single authz ceiling | 1000 | 1000 | 0 errors, ~2.2K req/s |
| Batch throughput | 50 x batch_30 | 1,500 decisions | ~7.4K decisions/s |
| Error storm (malformed) | 200 | 200 | 100% fail-closed DENY |
| Mixed valid + malformed | 300 | 300 | 100% correct categorization |
| Sustained ceiling | 2000 | 2000 | 0 errors, ~2.5K req/s |

All stress tests verify correctness, not just throughput. Every response is
validated against expected ALLOW/DENY decision. Error requests must return
200 with DENY decision (fail-closed), not 500.

For comparison: AVP's default service quota is 200 `IsAuthorized` requests/second
(requestable up to 1,000). This PDP sustains 2,500+ req/s on a single core at
c=2000 with zero errors, and 87K+ RPS on the native endpoint at c=100.
Latency is sub-millisecond (local eval) vs AVP's network round-trip to AWS.

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
| 1 | p50 | 0.025 ms | 0.085 ms | 3.4x slower |
| 1 | RPS | 30,215 | 8,685 | 0.29x |
| 10 | p50 | 0.095 ms | 0.427 ms | 4.5x slower |
| 10 | RPS | 84,774 | 17,254 | 0.20x |
| 50 | p50 | 0.260 ms | 2.788 ms | 10.7x slower |
| 50 | RPS | 132,925 | 8,902 | 0.07x |
| 100 | p50 | 0.417 ms | 11.283 ms | 27.1x slower |
| 100 | RPS | 141,292 | 6,765 | 0.05x |

**Key finding**: The Go external plugin IPC overhead is far worse than the
literature estimate (0.3-0.5ms). At concurrency 50, Go plugin adds ~2.5ms p50
vs Lua's 0.3ms -- a 10.7x overhead, not 3-5x. At concurrency 100, Go throughput
collapses to 6.8K RPS vs Lua's 141K RPS (95% reduction).

**Root cause**: Kong's external plugin protocol makes 3-5 PDK calls per request
(GetConsumer, GetMethod, GetPath, Response.Exit), each a separate MessagePack-
serialized Unix socket round-trip. At high concurrency the socket queue saturates.
Lua plugins make the same PDK calls as in-process Lua/C function calls with zero
serialization or IPC.

**Direct PDP** (bypass Kong) sustains 430K RPS at concurrency 100, confirming
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

## Security Findings

### Empty-org policy bypass (fixed)

The `org_scoped_access.cedar` permit compared `principal.org == resource.owner_org`
without guarding against empty/missing values. When `claims.org` was absent, both
attributes defaulted to `""`, causing the equality check to pass and granting
read+write access to any user with only a `sub` claim (no org, no roles, no scopes).

**Fix (defense in depth):**
1. Entity builder (`entities.rs`): missing `claims.org` now maps to `"__unset__"` sentinel instead of `""`.
2. Policy (`org_scoped_access.cedar`): added guard clause `principal.org != "" && principal.org != "__unset__"`.

Both layers must fail for the bypass to recur. Found via policy interaction testing (policy_coverage.rs).

## Optimization Tracks (Not Yet Implemented)

### Batch admission control (RT-26 AGI-Acc F2)

The 100-item batch cap prevents oversized single requests but provides no
per-second backpressure. At 1000 concurrent clients each sending 100-item batches,
the rayon thread pool absorbs the CPU load but there is no mechanism to reject or
queue excess requests before they enter evaluation. A `tower::ConcurrencyLimit`
layer on the batch endpoint (e.g., max 32 concurrent batch evaluations) would
bound the in-flight work and return 503+Retry-After when saturated.

### Entity construction caching (RT-26 AGI-Acc F1/F4)

Entity construction from JWT claims costs ~10.7 us per request -- the same order
of magnitude as Cedar evaluation itself (~9.6 us with production policies). For
agent workloads where the same role/org/tier patterns repeat across thousands of
requests, a small LRU cache of pre-validated entity sets (keyed on the claims
hash) could serve the majority of requests from a lookup. At 50 roles per agent
delegation chain, entity construction reaches ~93 us, making this optimization
increasingly valuable as role counts grow. This is premature for current
human-request workloads but becomes load-bearing at agent scale.
