### Bryan Cantrill -- Systems Programmer, DTrace / Oxide Computer
> You built the world's fastest authorization engine, then handed it a Go IPC tax bill. The performance story here is either dishonest or unexamined.

**Persona characterization** (no persona file found; constructed from public record): Cantrill is the author of DTrace, co-founder of Oxide Computer, longtime Rust advocate. His analytical lens: (1) every abstraction has a cost -- name it in nanoseconds or you are lying; (2) the kernel/hardware boundary teaches you that IPC is expensive and you should never pay it casually; (3) Rust is the correct answer for systems work, Go is not, and anyone who disagrees should produce the flamegraph; (4) formal verification (which Cedar has) is genuinely rare and deserves credit.

---

#### Findings

| # | Finding | Severity | File:Line | Detail |
|---|---------|----------|-----------|--------|
| 1 | Go plugin is an unforced IPC tax on a sub-ms engine | P1 | `kong-plugin-architecture.md:139-151` | The benchmark is unambiguous: -25% throughput, +0.34ms floor cost from empty Go plugin IPC. Cedar evaluates in ~0.1-1ms (cedar-policy-language.md:172). You've built a ~42-81x faster engine than OPA, then paid a fixed ~0.3-0.5ms IPC toll that is 30-500% of the evaluation cost itself. That is not a configuration choice, that is an architecture mistake. |
| 2 | arc-swap Cache wrapper omission is a performance regression waiting to happen | P1 | `rust-pdp-service-architecture.md:124` | The docs say "Cache wrapper provides 10-25x speedup for hot-path reads." The PolicyStore code shown at lines 96-117 does NOT include a Cache wrapper -- it calls `self.policy_set.load()` raw. Under high read concurrency, ArcSwap::load() still has to touch the global reference count. Cache::load() amortizes that across a thread-local epoch. At PDP throughput (every request is a read), this is not a micro-optimization. It's load-bearing. |
| 3 | Fail-open config flag is a landmine | P0 | `kong-plugin-architecture.md:67`, `rust-pdp-service-architecture.md:216-220` | The Go plugin Config struct has `FailOpen bool`. The PDP error handling correctly defaults deny (service-architecture.md:216-220). But the PLUGIN layer has an opt-in fail-open path that is a single boolean away from "the authz system is down and everything is permitted." This is not a circuit breaker -- it's a trapdoor. An ops engineer under pressure will flip it. There is no mention of audit logging, alerting, or time-bounded fail-open. The docs treat this as a configuration option rather than a security decision requiring ceremony. |
| 4 | HTTP/JSON vs gRPC overhead is understated for the Cedar request shape | P2 | `rust-pdp-service-architecture.md:43-61`, `kong-plugin-architecture.md:174-178` | A typical Cedar authz request includes a principal string, action string, resource string, context record, and an entities array. The entities array is the expensive part -- it can contain role memberships, group hierarchies, attributes. HTTP/JSON will serialize all of that to UTF-8 text and parse it back. gRPC/protobuf uses binary encoding with field tags. For a flat PARC tuple with no entities array, the difference is minimal (~50-200 bytes). For a realistic request with 5-10 entity relationships, the difference compounds. The docs dismiss this as "simpler vs lower overhead" without quantifying it. |
| 5 | cedar-local-agent push API is not evaluated against arc-swap + notify | P2 | `rust-pdp-service-architecture.md:130-133` | The tension point asks arc-swap + notify vs cedar-local-agent push API. The architecture file lists both as reload triggers but doesn't analyze cedar-local-agent's actual push semantics, its 15-second polling floor, or whether it supports push at all vs. just pull-with-ttl. The recommendation defaults to file-watching without confronting the multi-instance coordination problem: if you have 3 PDP sidecars and reload from a local file, they can diverge on policy version during the reload window. |
| 6 | Entity resolution security boundary is stated but not enforced | P1 | `rust-pdp-service-architecture.md:156-159` | "PDP should NOT trust entity data from PEP for security-critical attributes" is documented. But the API design (lines 43-61) accepts an `entities` array in the request body -- it's in the JSON schema. There is no specification of which entity attributes are PEP-supplied vs. PDP-authoritative. The JWT-to-Cedar mapping in entitlement-translation.md:129-155 constructs entities entirely from JWT claims. A compromised PEP (or a crafted JWT) can inject arbitrary entity attributes. The security claim is aspirational, not architectural. |

---

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Performance correctness -- Go plugin vs Lua | 0.45 | Recommending Go+HTTP as the start point is defensible for development velocity, but framing it as the default path ignores that the IPC floor cost is not recoverable. The 25% throughput number should be a blocker for any latency-sensitive deployment, not a footnote. |
| Performance correctness -- HTTP vs gRPC | 0.60 | The analysis exists but stops at "lower overhead" without byte counts or parse benchmarks for the actual Cedar request shape. For a flat PARC tuple this barely matters; for entity-heavy requests it can matter a lot. |
| Performance correctness -- arc-swap usage | 0.55 | arc-swap is the right choice over RwLock for this read-dominated workload. The choice is correct. The Cache wrapper omission in the implementation is wrong. The docs describe the 10-25x speedup and then the code doesn't use it. |
| Performance correctness -- sidecar vs remote | 0.80 | Sidecar is clearly the right call for latency. The 1-3ms vs 3-10ms+ difference is real and the co-location argument is sound. Availability coupling is acknowledged. This is the best-analyzed tension point in the document. |
| Security architecture | 0.40 | Fail-open trapdoor (P0), entity trust boundary aspirational not enforced (P1), and no mention of mTLS between plugin and PDP sidecar -- all on a same-host deployment where the attack surface is "can you write to the Unix socket?" |
| Overall | 0.55 | The Rust + Cedar engine selection is correct and well-justified. The surrounding architecture has real problems: IPC tax, missing Cache wrapper, a fail-open option that should not exist without ceremony, and a security boundary described in prose but not enforced in the API contract. |

---

#### Assessment

Cedar's performance story is legitimate. The formal verification via Lean proofs and 42-81x speedup over OPA is not marketing -- it is a genuinely well-engineered engine, and choosing it over Rego for an API gateway PDP is the right call. The sub-millisecond evaluation guarantee from a non-Turing-complete language is a systems property you can reason about, unlike OPA's unconstrained Rego.

The Rust implementation stack (axum + tonic + arc-swap + moka) is also correct. These are the right tools. arc-swap over RwLock for a 99.99% read workload is the correct choice: RwLock under read contention is a cache-line battleground, and arc-swap's epoch-based reference counting sidesteps it. The validation-before-swap pattern (service-architecture.md:112-113) is exactly right -- you never swap in a broken policy set.

But then we get to Kong integration and the analysis loses its nerve. The Go plugin IPC overhead is documented as -25% throughput and +0.34ms floor cost. For a Cedar evaluation that itself takes 0.1-1ms, paying 0.3-0.5ms in IPC to get to the evaluator is like hiring a Ferrari driver and making them take the bus to the track. The Lua option (kong-plugin-architecture.md:177, option C) eliminates this entirely. The document recommends "start with Go, migrate to Lua if IPC overhead matters" -- but by the time you've done the Go plugin, built your deployment pipeline, written your configuration management, and shipped it, the migration cost is real. The question should be asked at design time: what is your latency budget? If any latency matters, start with Lua. If development velocity is the only constraint, Go is fine and you should say so explicitly rather than hiding behind "if IPC overhead matters."

The Rust PDK deserves one honest sentence: 21 stars, 14 commits means it is an experiment, not a product. Do not use it. But the reason to note it is that in 18 months it may be the correct answer, and the architecture should be designed so that the plugin is swappable.

On entity resolution: the architecture is sound in theory and weak in implementation. The security note says PDP should not trust PEP-supplied entity data for security-critical attributes (service-architecture.md:156-159), but the API accepts an entities array unconditionally. Either the PDP must validate which attributes it will accept from the wire (with an explicit allowlist), or the API must not accept entity data at all (PDP resolves everything from authoritative sources). The current design invites a class of privilege escalation attacks where a crafted request injects favorable entity attributes. This is not hypothetical -- it is the exact attack vector that Cedar's "stateless, caller supplies all data" model enables if the caller is not trusted.

Before this ships, I want to see: (1) Cache wrapper added to the PolicyStore hot path; (2) the fail-open option removed or replaced with a time-bounded, audit-logged, alerting-triggering circuit breaker; (3) an explicit API contract specifying which entity attributes are accepted from the PEP and which are resolved by the PDP; (4) a Lua plugin prototype with a measured latency comparison against the Go plugin on the actual Cedar request shape being sent.

---

#### Deliberation Addendum

**Positions revised**:
- F1 (Go plugin IPC tax): Reframed from "you chose Go wrongly" to "you produced an architecture document for a latency-sensitive path without stating a latency SLA." Fowler's point is correct -- without a stated p99 budget, "start with Go" is defensible. The missing artifact is the SLA, not the language choice. Severity holds at P1 but the finding is now more precisely targeted.
- F6 (entity trust boundary): Downgraded from unconditional P1 to conditional. Schneier correctly identified that I conflated threat models. Severity is P1 if PDP is sidecar-only (compromising the PDP requires first compromising Kong); P0 if PDP has any external network exposure. The unspecified network exposure model is itself a finding -- implementers will make different choices without guidance.
- F6 (JWT entity trust mechanism): Refined. My original claim "JWT claims are inherently untrusted" was too broad. Fowler correctly noted that JWT role membership is as trustworthy as the signing key, given Kong's JWT validation at priority 1450 runs before our plugin at 950 (kong-plugin-architecture.md:86). The real gap: the architecture doesn't specify whether the PDP trusts Kong's upstream JWT validation or re-validates independently. That undefined policy is the finding, not blanket JWT distrust.

**Positions reinforced**:
- F3 (fail-open trapdoor, P0): Both Fowler and Schneier independently classified this as P0. `FailOpen bool` at kong-plugin-architecture.md:67 is not a circuit breaker. No audit trail, no alerting, no time bound. Three panelists in agreement. The Config struct should not have this field.
- F2 (arc-swap Cache wrapper omission, P1): Unchallenged by any panelist. The PolicyStore hot path at service-architecture.md:96-117 calls `ArcSwap::load()` without the Cache wrapper despite the documented 10-25x speedup. Missed optimization on the highest-frequency code path in the service.

**New observations**:
- Schneier raised mTLS absence between plugin and PDP sidecar. An unauthenticated HTTP channel on localhost means any process on the same Kong node can call the PDP. The right answer is mTLS with client cert pinned to the Kong plugin identity, or a Unix domain socket. Adding as P1.
- Schneier raised batch endpoint unbounded size cap. Cedar's O(n^2) worst case on set containment (cedar-policy-language.md:174) plus an unbounded requests array (service-architecture.md:86-89) is a legitimate DoS vector. I had serialization concern at P2 but the size cap gap is P1.
- The network exposure model being unspecified is a stand-alone finding: the architecture document should declare the expected deployment topology and PDP network accessibility as a prerequisite to all security reasoning.

**Score changes**:
- Security architecture: 0.40 -> 0.35. Adding mTLS gap and unspecified network exposure model weakens the posture further. Three independent panelists converged on P0/P1 security issues the document doesn't address.
- Overall: 0.55 -> 0.50. The engine selection and Rust stack remain correct. The security architecture gaps (fail-open trapdoor, missing mTLS, undefined network exposure model, unspecified JWT re-validation policy) collectively represent a document that has the performance story right and the security story aspirational.

---

#### Final Positions (Rounds 2-3 updates)

**DHH's Cedar-vs-OPA challenge -- holding Cedar:**

DHH's "IPC dominates so Cedar's speed is moot" argument is a category error. OPA's Kong Enterprise plugin also makes an HTTP POST to a local sidecar (kong-plugin-architecture.md:118-129). The IPC overhead is identical regardless of engine. The comparison is Cedar-over-HTTP vs OPA-over-HTTP. On that basis Cedar wins on two dimensions that matter operationally: (1) tail latency -- Cedar's bounded, non-Turing-complete evaluation produces tight p99/p999; OPA's unconstrained Rego does not guarantee this; (2) CPU footprint per decision at scale. The OPA ecosystem advantage (policy management APIs, decision logging, mature Kong integration) is real and worth naming -- OPA is the right choice if buying operational maturity at the cost of performance headroom. Cedar is right if the authorization layer must not become a bottleneck as load grows. The architecture should state which constraint applies.

**Antirez's thin Lua + thick PDP -- fully endorsed:**

The evolved proposal (thin Lua HTTP client, all logic in Rust PDP) is architecturally correct and I'm now fully behind it. Plugin responsibility: extract principal ID and request context from PDK, POST to PDP, enforce decision. Entity resolution, JWT decoding, hierarchy construction -- all in the PDP where it has database access and can be tested in isolation. This also resolves the entity trust boundary finding structurally: if the plugin sends only principal ID + method + path, there is no `entities` array injection surface. The security boundary becomes architectural rather than aspirational prose. Revised recommendation: thin Lua + thick Rust PDP supersedes the Go+HTTP starting point.

**Lamport's Arc<(PolicySet, Schema)> tuple question:**

A single `ArcSwap<Arc<(PolicySet, Schema)>>` is sufficient for correctness -- PolicySet and Schema are atomically swapped as a pair, so no reader sees a version mismatch between them. This is the right fix for torn reads. It does not address the Cache wrapper gap. The hot path calling `ArcSwap::load()` on every request still touches the global epoch counter on each call. `Cache::load()` uses a thread-local copy refreshed lazily on write. These solve different problems: tuple swap = correctness (torn reads eliminated); Cache wrapper = performance (hot-path throughput). Both are needed; the current code has neither the tuple swap nor the Cache wrapper.

**Cedar skip-on-error (Schneier's finding -- upgrading to P1):**

Cedar skips policies that error during evaluation rather than denying (cedar-policy-language.md:46-52). A crafted request can cause a `forbid` policy to error by omitting a required entity attribute, allowing `permit` policies to fire uninhibited. The fix requires pre-eval schema validation of incoming entity data with validation failure treated as deny -- not passed through to evaluation. This changes the hot path to: validate entities against schema -> `is_authorized`. The current error handling at service-architecture.md:216-220 catches evaluation errors but does not address the skip-on-error semantic gap. Upgrading to P1. Pre-eval validation must be mandatory and benchmarked; the architecture doc must make it explicit.

**Final score revisions:**
- Overall: 0.50 -> 0.45. The skip-on-error gap is a genuine P1 that I missed in Phase 1. An authorization engine that can be manipulated into skipping its `forbid` policies via crafted entity omissions, in a document that doesn't mandate pre-eval validation, represents a meaningful security gap on top of the already-noted issues.
- Cedar engine selection: holding. DHH's challenge doesn't change the engine choice -- it sharpens the conditions under which Cedar is correct (performance headroom matters, tail latency matters). The choice is right for the right reasons.
