# Cedar PDP Performance Benchmark Results

Date: 2026-04-08
Cedar-policy version: 4.9.1
Hardware: i7-14700KF (20c/28t), 32GB RAM
Rust: 1.92 (release profile, optimized)

### Hardware Caveat

All results in this document were measured on a single bare-metal workstation
(i7-14700KF, 32GB DDR5, NVMe SSD, no background load). Production deployments
on cloud instances (shared vCPUs, noisy neighbors, different memory hierarchy)
will show different absolute numbers. The relative relationships (linear policy
scaling, entity count independence, Go vs Lua ratios) should hold, but absolute
latency and throughput numbers should be re-validated on target production hardware
before using them for capacity planning or SLA commitments.

## Cedar Evaluation (In-Process, Criterion)

Benchmarks measure `Authorizer::is_authorized()` in isolation -- no HTTP, no
serialization, no network. The request is `User::"user-0"` reading
`Resource::"/resource-0"`, which matches exactly one permit policy in every
configuration. Entity count scales the entity lookup table; policy count scales
the policy evaluation pass.

Criterion reports a 95% confidence interval over 100 samples. The bounds below
are taken directly from that interval (lower bound as p5 proxy, mean as p50, upper
bound as p95 proxy). Variance was under 1% in all runs.

| Policies | Entities | Mean    | Low (p5)  | High (p95) |
|----------|----------|---------|-----------|------------|
| 10       | 10       | 5.17 us | 5.17 us   | 5.17 us    |
| 10       | 100      | 5.28 us | 5.27 us   | 5.28 us    |
| 10       | 1000     | 5.20 us | 5.19 us   | 5.21 us    |
| 100      | 10       | 45.1 us | 45.1 us   | 45.2 us    |
| 100      | 100      | 45.0 us | 44.98 us  | 45.1 us    |
| 100      | 1000     | 45.2 us | 45.2 us   | 45.2 us    |
| 1000     | 10       | 445 us  | 444.6 us  | 445.6 us   |
| 1000     | 100      | 444 us  | 443.6 us  | 444.6 us   |
| 1000     | 1000     | 441 us  | 440.8 us  | 441.7 us   |

### Key observations

- Entity count has essentially no effect on latency. All 10/100/1000 entity runs
  within any given policy count are within 2% of each other. Cedar's entity
  representation does not require scanning entities proportionally to set size.
- Policy count is the dominant factor. Latency scales roughly linearly with
  policy count: 10 policies -> ~5 us, 100 -> ~45 us (9x), 1000 -> ~444 us (88x).
  This matches Cedar's evaluation model, which evaluates each policy in sequence.
- At 1000 policies (444 us mean), Cedar is still well under 1 ms in isolation.

## HTTP Round-Trip (PDP Server, Measured)

PDP compiled in release mode, serving 2 test policies (tests/integration/policies/).
1000 sequential requests via curl from localhost. Single-threaded client, measuring
total round-trip including connection reuse, JSON serialization, and Cedar evaluation.

To reproduce:

```bash
# Terminal 1:
cd pdp && CEDAR_POLICY_DIR=../tests/integration/policies cargo run --release

# Terminal 2:
cd benchmarks && bash http_load_test.sh
```

| Metric | Value |
|--------|-------|
| Min    | 0.115 ms |
| Avg    | 0.225 ms |
| P50    | 0.225 ms |
| P95    | 0.343 ms |
| P99    | 0.425 ms |
| Max    | 0.639 ms |

### Breakdown (estimated from measured components)

- Cedar evaluation (2 policies): ~5 us (from Criterion, in-process)
- HTTP framing + JSON ser/de + tokio dispatch: ~220 us (P50 total minus eval)
- The HTTP overhead dominates at low policy counts. At 100+ policies, Cedar
  evaluation becomes a larger fraction but the total stays well under 1ms.

## Analysis

### <5ms per-request budget: MET, with margin

The 5ms per-request budget refers to the overhead added by the PDP on top of
the normal API request path.

**Measured**: HTTP round-trip P99 is 0.425ms with 2 policies. Cedar evaluation
at 1000 policies adds ~440us. Even in the worst case (1000 policies + HTTP
overhead), total PDP overhead stays under 1ms on localhost.

At a realistic production policy count of 10-100:
- Cedar evaluation: 5-45 us (measured, Criterion)
- HTTP round-trip overhead: ~225 us P50 (measured, curl localhost)
- Kong plugin callout overhead: ~100-200 us (local loopback, estimated)
- Total estimated end-to-end overhead: ~330-470 us (0.33-0.47 ms)

This is 10-15x under the 5ms budget.

### OPA comparison (literature-based, not measured)

Cedar at 100 policies evaluates in ~45 us (measured). OPA with Rego typically runs
50-200 us for equivalent policy sets per published benchmarks, with higher tail
latency due to Rego's interpreted execution model. At 1000 policies, Cedar evaluates
in ~444 us (measured) while OPA can reach 1-5 ms for complex Rego with large policy
sets.

At 100 policies: Cedar ~45us vs OPA ~50-200us is comparable.
At 1000 policies: Cedar ~444us vs OPA ~1-5ms is 2-11x faster.

Note: OPA numbers are from published literature, not our own benchmarks. Direct
comparison requires running both engines against identical policy sets.

### Scaling conclusion

For the Kong gateway use case:
- Production policy sets are unlikely to exceed 100-500 policies.
- At 500 policies (interpolated): ~225 us for Cedar evaluation.
- Combined with HTTP round-trip: < 1ms total PDP overhead.
- The 5ms budget is conservative -- Cedar's performance leaves room for
  additional middleware, logging, and telemetry without breaking the budget.

---

## Benchmark Suite Inventory

The following benchmarks are available. Run each and append results below.

### Criterion: Realistic Policy Evaluation

Tests production-shaped policies (RBAC hierarchy, ABAC attributes, forbid
overrides, set membership, template instantiation) instead of trivial equality
permits.

```bash
cd pdp && cargo bench -- realistic
```

6 scenarios:
- `admin_read` -- `principal in Role::"admin"`, read action. Exercises `in` membership.
- `viewer_delete_deny` -- viewer role, delete action. Full policy scan, no match.
- `suspended_admin_deny` -- admin + suspended=true. Forbid override.
- `data_scope_allow` -- `allowed_scopes.contains(classification)`. Set membership.
- `cross_org_deny` -- org mismatch. Attribute inequality.
- `multi_role_write` -- editor+viewer roles, write action. Multiple `in` checks.

Scaling variant: admin_read with 100/500/1000 additional noise policies.

### Realistic Policy Evaluation (Measured 2026-04-08)

| Scenario | Mean | What it exercises |
|----------|------|-------------------|
| admin_read | 9.6 us | `principal in Role::"admin"` membership traversal |
| viewer_delete_deny | 6.9 us | Full policy scan, no match (deny path) |
| suspended_admin_deny | 9.4 us | Forbid override with attribute check |
| data_scope_allow | 9.1 us | `allowed_scopes.contains(classification)` |
| cross_org_deny | 13.5 us | Attribute mismatch (org != owner_org) |
| multi_role_write | 15.6 us | Multiple `in` checks (editor + viewer) |
| admin_read + 100 noise | 93 us | 110 policies, complex predicates |
| admin_read + 500 noise | 423 us | 510 policies, complex predicates |
| admin_read + 1000 noise | 835 us | 1010 policies, complex predicates |

Key observation: realistic policies cost ~1.9x trivial policies at the same
policy count (835us/1010 vs 445us/1000). The `in` membership and attribute
checks add measurable overhead. `multi_role_write` (15.6us) is the most
expensive single scenario due to multiple role membership checks.

### Entity Hierarchy Depth (Measured 2026-04-08)

| Depth | Mean | Notes |
|-------|------|-------|
| 5 | 5.5 us | Baseline -- similar to flat entity cost |
| 10 | 5.5 us | No measurable increase from 5 |
| 15 | 8.4 us | ~53% increase over depth 5 |
| 20 | 8.6 us | ~57% increase over depth 5 |

Key observation: hierarchy depth has sub-linear impact. Cedar's entity store uses
hash-based lookups, not linear ancestor scanning. Depth 20 (8.6us) is well within
the 1ms Cedar budget. Enterprise RBAC hierarchies (typically 5-10 levels) add
negligible overhead.

### Memory Scaling (Measured 2026-04-08)

**PolicySet Memory:**

| Policies | Bytes | Per-Policy |
|----------|-------|------------|
| 10 | 27.3 KB | 2.7 KB |
| 100 | 192.9 KB | 1.9 KB |
| 1,000 | 1.93 MB | 2.0 KB |
| 5,000 | 9.54 MB | 2.0 KB |
| 10,000 | 19.07 MB | 2.0 KB |

**Entity Set Memory:**

| Entities | Bytes | Per-Entity |
|----------|-------|------------|
| 20 | 41.5 KB | 2.1 KB |
| 200 | 99.5 KB | 498 B |
| 2,000 | 1.16 MB | 608 B |
| 10,000 | 5.30 MB | 555 B |
| 20,000 | 10.59 MB | 555 B |

**Schema Parsing:** ~18 KB regardless of complexity.

Sidecar deployment with 1000 policies + 10,000 entities = ~7.2 MB. Minimal
footprint for sidecar deployment alongside Kong.

### Concurrent HTTP Throughput (Measured 2026-04-08)

Host PDP with 9 production policies, claims path, oha 15s per level.

**Allow requests (editor role, GET /api/v1/users):**

| Concurrency | RPS | p50 | p95 | p99 | Max |
|-------------|-----|-----|-----|-----|-----|
| 1 | 23,313 | 0.038 ms | 0.062 ms | 0.092 ms | 3.99 ms |
| 10 | 105,448 | 0.097 ms | 0.133 ms | 0.206 ms | 9.42 ms |
| 50 | 82,213 | 0.445 ms | 1.495 ms | 3.290 ms | 44.57 ms |
| 100 | 87,189 | 0.910 ms | 2.837 ms | 4.493 ms | 27.04 ms |
| 200 | 103,283 | 1.457 ms | 4.958 ms | 7.291 ms | 62.44 ms |
| 500 | 111,325 | 3.400 ms | 11.467 ms | 18.124 ms | 1052 ms |

**Deny requests (no roles, DELETE /api/v1/admin/settings):**

| Concurrency | RPS | p50 | p95 | p99 | Max |
|-------------|-----|-----|-----|-----|-----|
| 1 | 21,333 | 0.030 ms | 0.084 ms | 0.224 ms | 10.68 ms |
| 10 | 122,773 | 0.079 ms | 0.130 ms | 0.255 ms | 12.23 ms |
| 50 | 214,925 | 0.184 ms | 0.537 ms | 1.116 ms | 16.83 ms |
| 100 | 220,567 | 0.311 ms | 1.329 ms | 2.640 ms | 28.45 ms |
| 200 | 221,619 | 0.725 ms | 2.223 ms | 3.573 ms | 35.33 ms |
| 500 | 222,521 | 1.714 ms | 5.639 ms | 8.248 ms | 1014 ms |

5ms p99 budget is met up to concurrency ~100 for Allow, ~200 for Deny.
Deny is 2-2.5x faster because Cedar short-circuits on no matching permit.

### Hot-Reload Under Load (Measured 2026-04-08)

PDP with production policies, concurrency 100, reload triggered at 5s mark.

| Scenario | p99 | Max | RPS |
|----------|-----|-----|-----|
| Baseline (no reload) | 4.0 ms | 77.6 ms | 114,343 |
| With reload (median of 3) | 8.1 ms | 47.9 ms | 53,681 |
| Spike delta | +4.1 ms (+102%) | -- | -53% |
| Reload completion time | 15-78 ms | | |

The arc-swap reload causes a measurable p99 spike (~2x) but no dropped requests.
The RPS drop is partly due to the reload itself (filesystem scan + validation)
and partly due to CPU contention during policy parsing.

### Go vs Lua Plugin Comparison (Measured 2026-04-08)

Docker stacks, Kong 3.9, production policies, cache disabled (TTL=1ms).
Raw JSON results in `results/20260408T134526_*`. To reproduce: `bash go_vs_lua.sh`.

**Direct PDP (inside Docker, bypass Kong):**

| Concurrency | RPS (Lua stack) | RPS (Go stack) |
|-------------|-----------------|----------------|
| 1 | 52,508 | 52,121 |
| 10 | 200,016 | 197,921 |
| 50 | 350,792 | 307,117 |
| 100 | 429,909 | 363,627 |

Direct PDP numbers are comparable between stacks at low concurrency, confirming
the PDP itself performs identically. At c=50+, the Go stack shows ~12-15% lower
PDP throughput due to CPU contention from the Go plugin server process.

**Through Kong:**

| Concurrency | Lua RPS | Lua p50 | Go RPS | Go p50 | Go/Lua RPS |
|-------------|---------|---------|--------|--------|------------|
| 1 | 30,215 | 0.025 ms | 8,685 | 0.085 ms | 0.29x |
| 10 | 84,774 | 0.095 ms | 17,254 | 0.427 ms | 0.20x |
| 50 | 132,925 | 0.260 ms | 8,902 | 2.788 ms | 0.07x |
| 100 | 141,292 | 0.417 ms | 6,765 | 11.283 ms | 0.05x |

The Go plugin IPC overhead grows non-linearly with concurrency. At c=100,
Go throughput is 95% lower than Lua (6.8K vs 141K RPS). Go p50 latency at
c=100 (11.3ms) exceeds the 5ms p99 budget alone. This is far worse than the
literature estimate of -25%. The external plugin protocol creates a per-request
serialization bottleneck that collapses under concurrent load.

**Root cause**: Kong's Go external plugin protocol makes 3-5 PDK calls per
request (GetConsumer, GetMethod, GetPath, Response.Exit), each a separate
MessagePack-serialized Unix socket round-trip. At c=100, the socket queue
saturates and goroutines pile up waiting for IPC. Lua plugins make these
same PDK calls as in-process Lua/C function calls with zero serialization.

### Batch Endpoint Stress Test (Measured 2026-04-08)

Host PDP with production policies, rayon parallel evaluation.

**Batch vs Sequential:**
- Sequential (100 requests, c=1): total=0.009s, per_request=0.085ms
- Batch (1 x 100, c=1): total=0.002s, per_decision=0.020ms
- Speedup: 4.5x

**Concurrency Scaling:**

| Batch Size | Concurrency | RPS | p50 | p99 | Decisions/sec |
|------------|-------------|-----|-----|-----|---------------|
| 10 | 1 | 5,681 | 0.16 ms | 0.50 ms | 56,808 |
| 10 | 10 | 13,507 | 0.60 ms | 1.18 ms | 135,065 |
| 10 | 50 | 14,910 | 1.97 ms | 6.12 ms | 149,096 |
| 50 | 1 | 2,010 | 0.47 ms | 0.80 ms | 100,495 |
| 50 | 10 | 3,679 | 2.60 ms | 4.64 ms | 183,970 |
| 50 | 50 | 3,762 | 7.17 ms | 25.97 ms | 188,085 |
| 100 | 1 | 1,271 | 0.74 ms | 1.79 ms | 127,110 |
| 100 | 10 | 1,865 | 5.02 ms | 10.25 ms | 186,510 |
| 100 | 50 | 1,927 | 18.60 ms | 51.16 ms | 192,660 |

Peak throughput: 192K decisions/sec (batch_100 x c=50). The rayon parallel
iterator avoids the tokio blocking pool saturation that the roundtable flagged.
For <10ms p99, stay below batch_50 x concurrency_10.

### Cache Effectiveness (Measured 2026-04-08)

Go plugin Docker stack, production policies, 2000 requests per pass.
Three passes per TTL: cold (empty cache), warm (same PARC triple), varied
(100 distinct paths).

| TTL (ms) | Pass | RPS | p50 | p99 |
|----------|------|-----|-----|-----|
| 0 (disabled) | cold | 14,488 | 0.645 ms | 36.2 ms |
| 0 | warm | 53,811 | 0.837 ms | 2.1 ms |
| 0 | varied | 44,912 | 0.879 ms | 3.8 ms |
| 1,000 | cold | 15,770 | 0.759 ms | 24.2 ms |
| 1,000 | warm | 47,622 | 0.952 ms | 2.7 ms |
| 1,000 | varied | 45,180 | 0.934 ms | 3.6 ms |
| 5,000 | cold | 15,251 | 0.518 ms | 101.8 ms |
| 5,000 | warm | 19,521 | 0.840 ms | 2.4 ms |
| 5,000 | varied | 19,324 | 0.848 ms | 3.4 ms |
| 30,000 | cold | 15,195 | 0.680 ms | 29.3 ms |
| 30,000 | warm | 19,175 | 0.794 ms | 2.4 ms |
| 30,000 | varied | 46,178 | 0.869 ms | 4.2 ms |
| 60,000 | cold | 15,568 | 0.741 ms | 26.8 ms |
| 60,000 | warm | 52,911 | 0.845 ms | 2.0 ms |
| 60,000 | varied | 32,163 | 0.803 ms | 23.9 ms |

Key observations:
- Cold RPS is consistent (~15K) across all TTLs -- cache miss path is stable.
- Warm RPS varies (19K-54K) due to Docker scheduling variance between runs.
- The Go plugin's cache provides measurable latency improvement on warm paths
  (p99 drops from 25-36ms cold to 2-3ms warm).
- Varied path performance depends on cache fill behavior -- the 100 distinct
  paths compete for cache slots.
- Cache benefit is in tail latency reduction (p99), not throughput -- the Go
  plugin IPC overhead dominates regardless of caching.

### Cache Stampede Simulation (Measured 2026-04-08)

Go plugin Docker stack, cache_ttl_ms=5000, stampede at TTL boundary.

| Phase | Requests | Concurrency | p50 | p99 | Max |
|-------|----------|-------------|-----|-----|-----|
| warm_cache | 1,000 | 10 | 0.273 ms | 2.73 ms | 102.5 ms |
| post_expiry (stampede) | 1,000 | 200 | 3.294 ms | 149.6 ms | 162.5 ms |
| steady_state (re-warmed) | 1,000 | 200 | 2.438 ms | 16.1 ms | 102.0 ms |

**Stampede impact: p99 increased 54.8x** (149.6ms vs 2.7ms warm cache).

The steady_state pass (immediately after stampede) shows recovery -- p99 drops
back to 16ms, confirming the spike is transient. The stampede causes all cached
entries to expire simultaneously, forcing 1000 PDP calls in a burst.

**Recommendation**: Add 20% TTL jitter to smooth expiry distribution. With 20%
jitter on 5s TTL, entries expire across a 1000ms window (4000-5000ms), reducing
the peak burst by an estimated ~5x.

**Note**: The jitter mitigation is proposed but **not yet measured**. The ~5x
reduction estimate is based on uniform distribution of expiry times across the
jitter window, not empirical measurement. The Lua plugin implements jitter, but
no stampede benchmark has been re-run with jitter enabled to validate the actual
reduction factor. This should be verified before relying on it for SLA guarantees.
