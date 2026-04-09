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
    tests/                  #   integration, security, avp_security, admin_auth, concurrency, policy_coverage, avp_compat, reload_resilience, edge_cases, policy_evolution, etc. (248 tests)
    benches/                #   cedar_eval.rs, hierarchy_depth.rs, avp_format_overhead.rs, rayon_crossover.rs, etc. (8 Criterion benchmarks)
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
| `/avp/is-authorized` | POST | None | Single authorization (AVP wire format -- primary API) |
| `/avp/batch-is-authorized` | POST | None | Batch authorization, max 30 (AVP wire format -- primary API) |
| `/v1/is_authorized` | POST | None | Single authorization (legacy format with JWT claims auto-construction) |
| `/v1/batch_is_authorized` | POST | None | Batch authorization, max 100 (legacy format) |
| `/v1/policy-info` | GET | None | Policy count, last reload time, schema hash |
| `/admin/reload` | POST | Bearer `PDP_ADMIN_TOKEN` | Force policy reload from disk (rate-limited: 1 req/sec) |
| `/healthz` | GET | None | Liveness probe (always 200 if process is up) |
| `/readyz` | GET | None | Readiness probe (200 when policies loaded) |
| `/health` | GET | None | Backward-compat alias for `/readyz` |

All responses include:
- `X-Request-Id` header (propagated from request or generated UUID v4)
- `X-Policy-Epoch` header (millisecond timestamp of last policy reload -- plugins use this for cache key versioning)

### API Format

The PDP speaks the Amazon Verified Permissions (AVP) wire format. This is the
primary API -- not a compatibility layer. Clients use the same JSON request/response
format as AVP's `IsAuthorized` and `BatchIsAuthorized` operations. This enables
portability: teams can swap between this self-hosted PDP and AWS AVP without
changing client code.

Format details:
- Entity references: `{ "entityType": "T", "entityId": "id" }`
- Context: typed value wrappers (`{ "String": "foo" }`, `{ "Boolean": true }`, `{ "Long": 42 }`, `{ "Set": [...] }`, `{ "Record": {...} }`, `{ "EntityIdentifier": {...} }`)
- Entity hierarchy: explicit `entities.entityList`
- Decision: uppercase `ALLOW`/`DENY`
- Determining policies: `determiningPolicies: [{ policyId }]`
- Batch: same-principal-or-same-resource homogeneity constraint (30-item limit)
- `policyStoreId`: accepted but ignored (single-store deployment)

The `/v1/*` endpoints are a legacy format with JWT claims auto-construction --
the PDP builds Cedar entities from JWT claims rather than requiring the caller
to provide them. Whether entity construction belongs in the Kong plugin or the
PDP is a design decision for the team (see ADR-005 Tier 1 vs Tier 2 resolution).

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
# Runs 248 tests across 20 test files: core logic, AVP wire format, adversarial/fail-closed,
# concurrent correctness, admin auth, edge cases, pathological entity construction, schema hash
# stability, policy coverage, reload resilience, stress, policy evolution, and more.
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
- AVP wire format API (`/avp/is-authorized`, `/avp/batch-is-authorized`) -- primary endpoints
- Batch authorization with rayon parallel eval (4.5x speedup at 100 items)
- Go and Lua Kong plugins with fail-closed semantics
- Entity resolution from JWT claims (Tier 1)
- Integration test harness (Docker Compose, 6 tests passing)
- Criterion benchmarks (Cedar eval: 5-631us depending on policy count)
- Concurrent HTTP throughput benchmarks (oha-based, configurable concurrency)
- Go vs Lua plugin comparison infrastructure (Docker stacks, automated scripts)
- Cache effectiveness and stampede simulation benchmarks
- Admin endpoint authentication (`PDP_ADMIN_TOKEN` Bearer token) with rate-limiting (1 req/sec)
- Decision audit logging (structured tracing of every authorization decision with PARC, determining policies, eval latency)
- Skip-on-error detection (warn-level log when Cedar skips errored policies -- potential forbid bypass indicator)
- Policy epoch header (`X-Policy-Epoch`) for plugin-side cache invalidation on policy reload
- Plugin-side cache TTL jitter (+/-20%) to prevent stampede on simultaneous expiry
- Plugin-side cache key versioning (epoch-aware keys auto-invalidate on policy reload)
- Graceful shutdown (SIGTERM/SIGINT drain with in-flight request completion)
- Kubernetes-style health probes (`/healthz` liveness, `/readyz` readiness)
- X-Request-Id middleware (propagate or generate UUID v4 for log correlation)
- Configurable port via `PDP_PORT` env var (default 8180)
- Non-root container user in production Dockerfile

### AVP API Status

The authorization hot path is fully implemented and stress-tested. The PDP speaks
the AVP wire format natively. No code changes needed to swap between this PDP and
AWS AVP for authorization decisions.

**Implemented (165 tests passing, stress-tested to c=2000):**
- `IsAuthorized` -- single authorization
- `BatchIsAuthorized` -- batch authorization (30-item limit, homogeneity constraint)
- Typed value wrappers (String, Boolean, Long, Set, Record, EntityIdentifier)
- Explicit entity hierarchy via `entities.entityList`
- `policyStoreId` accepted (ignored in single-store deployment)
- Fail-closed: malformed requests always produce DENY with error, never 500
- Typed value parsing cost: +14 us per request (~108% of full eval path with 10 production policies; proportionally less with more policies)

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
| Decision audit logging (durable) | Persistent log of every authorization decision | PDP logs decisions via structured tracing (stdout). Durable storage requires logging infrastructure (CloudTrail equivalent), retention policy, query interface |

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
Numbers below are from the latest Criterion run (2026-04-09).
**See [benchmarks/RESULTS.md](benchmarks/RESULTS.md) for detailed results,
methodology, and the full benchmark inventory with reproduction instructions.**

**Hardware caveat**: All benchmarks were run on consumer-grade bare-metal hardware
(i7-14700KF desktop) with no background load. **These numbers are NOT representative
of cloud deployment performance.** Cloud instances with shared vCPUs, noisy neighbors,
and different memory hierarchies will produce materially different absolute latency
and throughput numbers. Expect 2-5x higher tail latencies on typical cloud VMs.
The relative relationships (linear policy scaling, Go vs Lua ratios, entity count
independence) should hold across hardware. **Re-run all benchmarks on target
production hardware before using these numbers for capacity planning or SLA
commitments.**

### Cedar Evaluation (In-Process, Criterion)

| Scenario | Policies | Mean | What it exercises |
|----------|----------|------|-------------------|
| Trivial permit (10 policies, flat) | 10 | 5.2 us | Equality check baseline |
| Trivial permit (100 policies, flat) | 100 | 50 us | Linear scaling validation |
| Trivial permit (1000 policies, flat) | 1000 | 631 us | Upper bound, simple policies |
| **Realistic: admin-read** | 10 prod | 17.5 us | `in` membership traversal (RBAC) |
| **Realistic: viewer-delete-deny** | 10 prod | 11.6 us | Full policy scan, no match |
| **Realistic: suspended-admin-deny** | 10 prod | 17.3 us | Forbid override |
| **Realistic: data-scope-allow** | 10 prod | 16.6 us | `.contains()` set membership |
| **Realistic: cross-org-deny** | 10 prod | 14.4 us | Attribute mismatch |
| **Realistic: multi-role-write** | 10 prod | 16.8 us | Multiple `in` checks |
| **Realistic + 100 noise** | 110 | 76 us | Complex predicates at scale |
| **Realistic + 500 noise** | 510 | 235 us | Complex predicates at scale |
| **Realistic + 1000 noise** | 1010 | 583 us | Complex predicates at scale |
| **Hierarchy depth 5** | 10 | 5.6 us | `in` traversal, 5-level DAG |
| **Hierarchy depth 10** | 10 | 7.7 us | `in` traversal, 10-level DAG |
| **Hierarchy depth 15** | 10 | 5.5 us | `in` traversal, 15-level DAG |
| **Hierarchy depth 20** | 10 | 8.2 us | `in` traversal, 20-level DAG |

### HTTP Round-Trip (PDP Server)

| Metric | Sequential (curl) | Concurrent (oha, c=100) |
|--------|-------------------|-------------------------|
| P50 | 0.225 ms | 0.910 ms |
| P95 | 0.343 ms | 2.837 ms |
| P99 | 0.425 ms | 4.493 ms |
| Max RPS | N/A (sequential) | 87,189 (Allow), 220,567 (Deny) |

Deny requests are faster because they short-circuit after finding no matching
permit (11.6us eval) vs Allow which must evaluate matching policies (17.5us+).
At concurrency 500, Allow sustains 111K RPS (p99=18ms), Deny sustains 222K RPS
(p99=8ms). The 5ms p99 budget is met up to concurrency ~100 for Allow requests.

### Typed Value Parsing Overhead (In-Process, Criterion)

The AVP format uses typed value wrappers (`{"String": "foo"}` instead of raw
`"foo"`). This adds a fixed parsing cost per request. Benchmarked against a
minimal format (raw Cedar UID strings, no typed wrappers) for reference:

| Scenario | Native Format | AVP Format | Overhead |
|----------|---------------|------------|----------|
| Parse only (no eval) | 12.2 us | 26.3 us | +116% |
| Full path (parse + eval) | 22.4 us | 46.7 us | +108% |
| Response serialization | 55 ns | 114 ns | negligible |
| Batch 10 (sequential eval) | 383 us | 417 us | +9% |
| Batch 30 (sequential eval) | 1.11 ms | 1.61 ms | +45% |

The ~14 us per-request overhead comes from typed value wrapper deserialization and
explicit entity construction. This is the cost of speaking the AVP format --
fixed per request, independent of policy count or Cedar evaluation time. At
production policy counts (10+ policies, 12+ us eval), it's proportional to the
Cedar evaluation cost and shrinks as policy complexity grows. For context,
the full AVP-format request round-trip at c=100 is still well under 5ms p99.

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
| Cedar eval per-policy cost | ~6.3 us/policy (trivial), ~1.5 us/policy (realistic) | Linear scaling |
| Policy count for 1ms Cedar budget | ~160 (trivial), ~700 (realistic) | Interpolated |
| HTTP overhead (localhost) | ~220 us | JSON ser/de + tokio dispatch |
| Memory per policy | ~2 KB/policy | Measured at 10K policies |
| Memory per entity | ~555 bytes/entity | Measured at 10K entities |
| Schema memory | ~18 KB | Production schema (ApiGateway) |
| Entity hierarchy depth budget | 20 levels = 8.2 us | `in` traversal, linear chain |
| Batch speedup vs sequential | 2.4x (100 decisions) | rayon parallel eval |
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
- **Cedar evaluation**: O(n) in policy count. 1000 policies = ~631us (trivial),
  ~583us (realistic with RBAC/ABAC noise scaling). Realistic noise policies are
  more selective, yielding faster scanning than trivial policies at high counts.
- **Entity hierarchy**: depth 1-10 = ~5-8us, depth 15-20 = ~5.5-8.2us. Sub-linear
  scaling -- Cedar's entity lookup is hash-based, not scan-based.
- **Hot-reload under load**: arc-swap reload adds ~4ms to p99 (+102%) at
  concurrency 100. Median reload completes in 15-21ms. No dropped requests.
- **Memory at scale**: 10K policies = 19 MB, 10K entities = 5.3 MB.
- **Sidecar cache**: No cross-instance invalidation. Stale window = TTL (30-60s).
  TTL jitter (+/-20%) mitigates stampede (implemented in Lua plugin; reduction
  factor estimated ~5x but not yet empirically verified -- see RESULTS.md).
  Cache keys include policy epoch from `X-Policy-Epoch` header -- stale decisions
  auto-invalidate on policy reload.
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

# Sustained load test -- p99 stability over 5+ minutes
cd benchmarks && bash sustained_load.sh
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

Entity construction from JWT claims costs ~10.7 us per request -- comparable to
Cedar evaluation itself (~11.6-17.5 us with production policies). For agent
workloads where the same role/org/tier patterns repeat across thousands of
requests, a small LRU cache of pre-validated entity sets (keyed on the claims
hash) could serve the majority of requests from a lookup. At 50 roles per agent
delegation chain, entity construction reaches ~105 us, making this optimization
increasingly valuable as role counts grow. This is premature for current
human-request workloads but becomes load-bearing at agent scale.
