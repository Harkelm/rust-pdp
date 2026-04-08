### DHH -- The Convention Pragmatist
> You built a distributed authorization bureaucracy to gate API calls, and the first question nobody asked is: do you actually need any of this?

#### Findings

| # | Finding | Severity | File:Line | Detail |
|---|---------|----------|-----------|--------|
| 1 | gRPC over localhost is theater | P1 | `kong-plugin-architecture.md:148-159` | The latency table shows Go+HTTP at ~2-4ms and Go+gRPC at ~1-3ms. You're saving 1ms on a localhost call you don't have to make at all if you cache the decision. The proto schema, generated stubs, and binary framing exist purely to feel modern. HTTP/JSON between two sidecar processes on the same host is not a bottleneck. |
| 2 | The whole sidecar pattern is the wrong level of abstraction | P1 | `rust-pdp-service-architecture.md:228-251` | Cedar is a Rust library (`cedar-policy = "4.9"`). The Go plugin calls over IPC to a Rust process that calls a Rust library. Why is the Rust library not embedded directly in the evaluation path? The architecture diagram shows Kong -> Go plugin -> Rust PDP -> PolicyStore, when it could be Kong -> Lua plugin (HTTP to a thin service) or just Kong -> Lua/Go with Cedar embedded. The sidecar exists to serve the PDP abstraction, not the user. |
| 3 | Cedar vs OPA: the business case is missing | P1 | `cedar-policy-language.md:183-198` | The comparison table asserts "Cedar is the stronger choice" because it's faster and Rust-native. But OPA has a production Kong Enterprise plugin that already does exactly this. Cedar has no management APIs, no built-in UI, no policy distribution tooling. The benchmark (42-81x faster than OPA) is lab throughput -- the bottleneck in this system is network I/O and entity resolution, not policy evaluation speed. The actual speed advantage is irrelevant at the scale this will run at. |
| 4 | Three resolution strategies for entity data is two too many | P2 | `rust-pdp-service-architecture.md:149-158` | "Static entities in ArcSwap, principal attributes from JWT, resource attributes from DB with TTL cache." This is three different data paths with three different consistency models. Every edge case (stale cache + fresh JWT + just-changed DB row) becomes a debugging nightmare. Start with request-time construction from DB (mentioned in `entitlement-translation.md:168-172` as "simplest for starting") and add caching only when you have latency measurements proving you need it. |
| 5 | Arc-swap + file watcher + SIGHUP + HTTP admin + periodic polling = four reload mechanisms | P2 | `rust-pdp-service-architecture.md:128-133` | Pick one. Four reload triggers means four code paths to test, four failure modes to handle, and four ways to get into a state where you think policies are current and they aren't. File watcher + HTTP admin endpoint is sufficient. SIGHUP is Unix trivia. Periodic polling is a fallback for when your file watcher is broken, which means you have a broken file watcher. |
| 6 | Fail-closed is the only defensible default -- but it's buried | P0 | `rust-pdp-service-architecture.md:215-222` | The fail-closed default is correct. The problem is `fail_open: bool` exists as a plugin config field (`kong-plugin-architecture.md:66-70`). This means operators can and will set it to true when they get a PDP outage at 2am. The field should not exist. If you want fail-open behavior for specific routes, that belongs in policy logic, not in the plugin config where it silently disables the security model. |

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Scope Discipline | 0.35 | Four reload mechanisms, three entity resolution strategies, both HTTP and gRPC endpoints, AuthZen AND Cedar-native API, arc-swap AND moka caches. Every decision adds a component instead of removing one. |
| Efficiency | 0.55 | Cedar itself is fast (sub-ms, well-chosen). The surrounding infrastructure defeats that advantage: IPC overhead, entity DB lookup per-request, cache TTL tuning, gRPC protocol negotiation. The fast engine is wrapped in slow plumbing. |
| Quality | 0.60 | The shadow-mode migration methodology (`entitlement-translation.md:213-229`) is genuinely good -- dual-run, parity verification, incremental cutover. That's the right approach. The policy model (PARC, forbid-overrides-permit, schema validation) is sound. The rest is over-built. |

#### Assessment

The core decision to use Cedar is defensible but the business case is never made. The cedar-policy language documentation (`cedar-policy-language.md:183-198`) claims Cedar is "the stronger choice for API gateway PDP" and justifies it with Rust-nativeness and a benchmark showing 42-81x faster evaluation than OPA. That benchmark is measuring the wrong thing. At API gateway scale -- let's say 1,000 RPS -- you're spending 1ms on Cedar evaluation and 3-9ms waiting for the Go plugin IPC and entity DB lookups. The performance advantage of Cedar over OPA is completely swamped by the architecture surrounding it. Meanwhile OPA has a Kong Enterprise plugin that exists and ships and has been debugged in production. You're choosing the newer, smaller-ecosystem option and then building all the operational tooling OPA would have given you for free.

The sidecar pattern is the central mistake. Cedar is a library. You embed libraries. You don't run a library as a service, add an IPC boundary, write a protocol buffer schema, generate stubs in two languages, and congratulate yourself on microservices. If you need Cedar at Kong, the right path is: write a Go function that calls a Cedar-compatible HTTP service (acceptable), or write a Lua plugin that calls a minimal HTTP endpoint (also acceptable), or find a way to embed evaluation in the plugin process (best). The current design has Kong owning a Go plugin process communicating over Unix sockets to a Rust process that wraps a Rust library. That is three process boundaries for a library call.

The `fail_open` config field (`kong-plugin-architecture.md:68`) is the one finding I'd call genuinely dangerous rather than merely over-engineered. It exists because someone anticipated operators needing it under pressure. But making security degradation a config toggle means it will be used. Security-critical systems don't get "easy off switches." If the PDP is down, requests should fail. That's the contract. If that's operationally unacceptable, fix PDP availability -- don't add a flag that makes the auth layer optional.

What I'd want before this ships: (1) a written argument for Cedar over OPA that addresses ecosystem maturity and operational tooling gaps, not just benchmark throughput; (2) entity resolution collapsed to one strategy (request-time from DB, cached with one TTL); (3) `fail_open` removed from plugin config entirely; (4) the gRPC endpoint dropped until you have a profiled reason to add it back.

#### Deliberation Addendum

**Positions revised**:
- Cedar skip-on-error as injection vector (`cedar-policy-language.md:50-51`) -- Schneier surfaced this in Round 3 and I missed it in my original analysis. An attacker who can craft requests inducing evaluation errors on specific forbid policies can bypass those denies, because erroring policies are skipped rather than treated as deny. Cedar documents this behavior explicitly. The mitigation (mandatory pre-evaluation schema validation) is mentioned as a feature but not enforced as an architectural constraint. Upgrading to P0 and adding as F7. My analysis was incomplete.
- Scope Discipline score: 0.35 -> 0.30. The skip-on-error attack surface adds a security complexity dimension I hadn't accounted for. More infrastructure, more attack surface, still no stated scale justification.
- Quality score: 0.60 -> 0.55. A P0 security gap in the core evaluation path pulls this down despite the shadow-mode migration methodology being genuinely good.

**Positions reinforced**:
- fail_open as P0: Cantrill, Schneier, and I all independently called this P0 with different framings. Cantrill: no audit trail, no time bound. Schneier: standing capability to bypass security without audit trail. Mine: security degradation should not be a config toggle. Three independent panelists, same conclusion. Position held.
- Cedar vs OPA build cost (F3): Challenged implicitly via Cantrill's Cedar performance defense. My counter -- the IPC overhead dwarfs Cedar's speed advantage over OPA in this architecture -- went unanswered. Nobody defended Cedar's lack of management APIs, policy distribution tooling, or operational maturity against OPA's existing ecosystem. Position held.
- Sidecar pattern (F2): Cantrill engaged on IPC tax from a Go-vs-Lua angle but didn't address the library-wrapped-in-service problem. Position held.
- Four reload mechanisms (F5): Unchallenged across all three rounds. Held at P2.

**New observations**:
- Fowler's PEP/PDP contract finding and Schneier's confused deputy finding are the same root cause from different angles. A written API contract specifying exactly what the plugin may pass vs what the PDP resolves independently would fix both findings and collapse the three-strategy entity resolution complexity.
- Schneier's JWT role claims finding adds an important nuance I'd add to my analysis: the "never trust PEP for security-critical attributes" rule needs explicit scoping by decision sensitivity. High-stakes paths (admin, billing, deletion) require independent PDP resolution. Low-stakes read paths can accept JWT claims with short TTL. The architecture says nothing about this distinction, which means the JWT path gets used everywhere by default because it's cheapest.
- No panelist in three rounds provided a stated deployment scale. Nobody said "this is for X RPS, therefore arc-swap is justified." That absence is itself a finding -- the architecture is designed without a scale target, which is why every component defaults to the maximally complex option.

**Score changes**:
- Scope Discipline: 0.35 -> 0.30 (see above)
- Quality: 0.60 -> 0.55 (see above)
- Efficiency: unchanged at 0.55
