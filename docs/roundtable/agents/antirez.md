### Antirez -- Backend Dev / Simplicity Purist
> "You have Kong calling a Go plugin calling HTTP calling a Rust service calling Cedar. That is four hops to answer a boolean question. Every hop is a place where you lose latency, add failure modes, and add operational surface. Show me what you gain that justifies each one."

#### Findings

| # | Finding | Severity | File:Line | Detail |
|---|---------|----------|-----------|--------|
| 1 | Decision cache has no stampede protection | P1 | `rust-pdp-service-architecture.md:163-178` | moka 10,000 entries, 60s TTL, `principal:action:resource` key. When 60s expires all entries for a busy service expire roughly together. Thundering herd hits the DB/Cedar simultaneously. No stale-while-revalidate, no jitter, no probabilistic early refresh. This is a classic cache stampede that will spike DB load on expiry boundaries. |
| 2 | Three-source entity resolution makes cache invalidation unsolvable | P1 | `rust-pdp-service-architecture.md:149-159` | Static entities in ArcSwap, principal attributes from JWT, resource attributes from per-request DB. Any of the three can change independently. The decision cache key (`principal:action:resource`) does not encode which entity version was used. So you cache a decision, static entities reload (arc-swap swap), and the cached decision reflects the old entity graph. The cache TTL is your only protection -- 60s of potential stale authorization. This is not a TTL problem, it is a key design problem. |
| 3 | Go plugin is the right choice but the recommendation buries it | P2 | `kong-plugin-architecture.md:173-181` | The matrix says "Start with A (Go + HTTP)". Good. But the framing of Lua as a cost-saving migration path is wrong. Lua in Kong is not just "lower IPC overhead" -- it is a completely different programming model (coroutine-based, no real concurrency, limited library ecosystem). The 0.3-0.5ms IPC savings from Lua vs Go are noise compared to the HTTP round-trip to PDP (1-3ms). Go is the right permanent choice, not a starting point. |
| 4 | Fail-closed is stated but not structurally enforced | P1 | `rust-pdp-service-architecture.md:215-222` | The error path returns `decision: false`. But `kong-plugin-architecture.md:65-68` shows `FailOpen bool` as a Config field. Fail-open is a one-line config change made by whoever deploys the plugin. The default is correct but the blast radius of misconfiguration is total -- every request gets through. Fail-open should not be a plugin config field; it should require a code change or at minimum a strongly-typed enum with an explicit "I know what I am doing" value. |
| 5 | arc-swap hot-reload pattern is correct but validation window is wrong | P2 | `rust-pdp-service-architecture.md:107-116` | `validate_before_swap` is shown as `new_policies.validate(&new_schema)` followed by two separate `store()` calls -- one for policies, one for schema. Between the two stores there is a window where policies reference the new schema but the schema store still holds the old one (or vice versa). Should be a single atomic operation: build a `(PolicySet, Schema)` pair behind a single `ArcSwap<(Arc<PolicySet>, Arc<Schema>)>`. The current pattern is correct 99.99% of the time and wrong in a narrow concurrent reload window. |

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Correctness | 0.60 | Decision cache key does not encode entity version. Arc-swap dual-store has a narrow but real atomicity gap. Fail-open as config is a correctness risk waiting to happen. |
| Efficiency | 0.65 | Cedar sub-ms evaluation is wasted if the Go->HTTP->Rust hop is 1-3ms. Sidecar deployment mitigates but is not enforced. Cache stampede will cause periodic DB spikes. |
| Quality | 0.70 | The overall pattern (arc-swap, moka cache, axum+tonic) is reasonable. The AuthZen interop endpoint is a good idea. Observability metrics are complete. The entity resolution layering is the primary design debt. |

#### Assessment

The arc-swap pattern for policy hot-reload is genuinely good. I built RDB/AOF with similar atomic swap semantics in Redis. Validate-before-swap is the right discipline -- you never serve a broken policy set. The dual `store()` on separate fields is a small gap, not a fundamental error, but it should be fixed: wrap `(PolicySet, Schema)` in a single `Arc` behind a single `ArcSwap`.

The entity resolution design is where I would focus scrutiny. Three data sources (ArcSwap static entities, JWT principal claims, per-request DB for resource attributes) creates a version coherence problem. The decision cache key is `principal:action:resource` -- a pure identity tuple. It does not encode whether the principal has changed roles since the cache was populated, whether the resource's classification changed, or whether the static entity graph was reloaded. You get a 60-second window of potentially stale authorization. For most APIs this is acceptable. For revocation (user fired, subscription cancelled) it is not. The architecture mentions "Never cache forbid decisions" but this does not solve the problem: the issue is cached `allow` decisions that should now be `deny`.

The simpler data model is: put everything you need for a decision in the JWT (roles, subscription tier, relevant resource attributes for the calling context) and maintain one cache layer keyed on a hash of the full entity state used at decision time. JWT-first reduces DB calls and makes cache invalidation tractable. The complexity of three-source entity resolution should be justified by what you cannot put in the JWT -- and that justification is absent from the architecture documents.

The Kong -> Go plugin -> HTTP -> Rust PDP -> Cedar chain is four hops. Cedar evaluates in sub-millisecond. The HTTP hop to the sidecar PDP is 1-3ms. The Go plugin IPC is 0.3-0.5ms. You are paying 1.5-4ms overhead for a 0.1-1ms operation. The efficiency ratio is wrong. This is the cost of the remote PDP pattern. The architecture should state explicitly: the reason to pay this cost is policy centralization, hot-reload without restart, and independent scaling. If you do not need those properties, embed Cedar in the Go plugin directly.

Before this ships: fix the arc-swap dual-store atomicity gap, add cache stampede protection (jitter or stale-while-revalidate), redesign the cache key to include entity version or hash, and make fail-open non-trivial to enable.

#### Deliberation Addendum

**Positions revised**:
- Arc-swap dual-store (F5): downgraded from P1 to P2. Lamport clarified that the Cedar evaluation path does not use Schema directly, so the two sequential `store()` calls are safe for authz decisions in practice. The single `Arc<(PolicySet, Schema)>` tuple fix is still the correct design -- it eliminates the problem class and produces simpler code -- but urgency is lower than originally scored.
- Decision cache: original findings were stampede (P1) and stale key design (P1). Revised position: skip the decision cache at MVP entirely. Cedar evaluates in 0.1-1ms; the bottleneck is the IPC + HTTP path at 1.5-4ms. The cache saves the smallest component of total latency while introducing stale revocation risk, stale post-reload decisions, stampede risk, and the "never cache forbid" half-effectiveness rule. Complexity cost exceeds the benefit. The entity cache (ArcSwap static entities) should be kept -- that avoids DB lookups on the hot path.

**Positions reinforced**:
- Fail-open (F4): held through all three rounds, challenged by nobody. Unanimous P0/P1 across all panelists. `FailOpen bool` must be replaced with an observable circuit breaker that denies on trip with mandatory recovery window.
- Entity trust boundary / cache key version coherence: held through all three rounds. Fowler, Cantrill, and Schneier all converged on the same structural problem from different angles. The `entities: [...]` array in the external API cannot express trust levels. The cache key has no staleness signal. Both require architectural fixes, not documentation.
- Cedar skip-on-error as injection vector (Schneier's F3): upgraded to P0. An attacker who can omit entity attributes causes specific forbid policies to skip, allowing a permit to fire. Mitigation requires mandatory pre-evaluation schema validation as a gate. The architecture shows schema validation at reload time only (`rust-pdp-service-architecture.md:112`), not at request evaluation time.
- Remote PDP justification gap: held. The architecture never states why the remote process exists. Policy centralization and hot-reload without Kong restart are the real reasons. The architecture defends Cedar on throughput benchmarks that do not survive contact with the actual bottleneck (IPC + network).

**New observations from other panelists**:
- Schneier's Cedar skip-on-error finding was the sharpest finding at the table -- no other panelist named it independently. The attack surface is real and requires a mandatory pre-evaluation schema validation gate.
- Fowler's AuthZen endpoint observation: `subject.properties` / `resource.properties` freeform bags (`rust-pdp-service-architecture.md:66-80`) widen the entity trust boundary problem. The AuthZen endpoint is structurally worse than the Cedar-native endpoint because the `properties` bags have no schema constraint visible in the API. The "map to Cedar types internally" note at line 83 is where the trust boundary must be enforced, and the architecture says nothing about how.
- Lamport confirmed the cache key version problem independently: under high fan-out, the cache serves decisions from unknown prior policy versions mixed with fresh evaluations. Reinforces the MVP conclusion to skip the decision cache.
- DHH's OPA challenge is unresolved as a pure design question. Cedar is defensible on correctness grounds (formal verification, non-Turing-complete evaluation, forbid-as-language-primitive). The architecture defends it on the wrong grounds (throughput benchmarks).

**Score changes**:
- Correctness: 0.60 -> 0.50. Schneier's skip-on-error attack surface is more severe than originally weighted. The entity trust boundary is a structural flaw. The cache coherence problem is compounded by Lamport's policy-version observation.
- Efficiency: 0.65 -> 0.70. Conceding that Go is the permanent correct choice (not a starting point) reduces one complexity concern. The IPC tax is real but bounded; the remote PDP pattern is justifiable if stated.
- Quality: 0.70 -> 0.65. The AuthZen endpoint adds an undocumented attack surface. The architecture's failure to state the remote PDP justification is a quality gap that will produce inconsistent implementations.
