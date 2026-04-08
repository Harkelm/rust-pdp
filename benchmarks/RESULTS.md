# Cedar PDP Performance Benchmark Results

Date: 2026-04-08
Cedar-policy version: 4.9.1
Hardware: i7-14700KF (20c/28t), 32GB RAM
Rust: 1.92 (release profile, optimized)

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
