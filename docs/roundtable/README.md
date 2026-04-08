## Roundtable RT-26: Cedar PDP + Kong Gateway Architecture Decision

### Panel
- **Leslie Lamport** (Distributed Systems) -- "The architecture has no written invariants, which means it has no correctness claims."
- **Bryan Cantrill** (Systems/Rust Performance) -- "You built the world's fastest auth engine, then handed it a Go IPC tax bill."
- **Martin Fowler** (System Architect) -- "The abstraction boundaries are muddled: the plugin is doing too much entity construction."
- **Kelsey Hightower** (DevOps/SRE) -- "Every hop you add is a call page at 3am."
- **Bruce Schneier** (Security) -- "A formally verified engine behind an informally trusted trust boundary -- that's where attackers go."
- **Mitchell Hashimoto** (Infrastructure Tooling) -- "Policy-as-code is not a feature, it's a lifecycle."
- **Antirez** (Simplicity/Data Structures) -- "Four hops to answer a boolean question."
- **DHH** (Build-vs-Buy Skeptic) -- "Do you actually need any of this?"
- **AGI Accelerationist** (Scale/Composability) -- "Cedar's entity model is a bottleneck for agent delegation chains."

### Consensus

These positions survived 3 rounds of deliberation unchallenged or defended:

1. **Cedar engine is the correct choice** (7/9). Formally verified, sub-ms evaluation, non-Turing-complete with bounded latency, Rust-native. DHH challenged on ecosystem grounds (OPA has management APIs, existing Kong plugin); panel held that Cedar's correctness properties justify the build cost, especially with AuthZen as an engine-swap escape valve. Antirez defended Cedar on formal verification, forbid-overrides-permit, and bounded eval -- not benchmarks.

2. **FailOpen bool must be removed** (9/9). Universal P0. Every panelist flagged independently. Replace with time-bounded emergency override requiring mandatory audit logging, security team alerting, and automatic expiry. Return 503+Retry-After for PDP unavailability (not 403).

3. **Entity trust boundary must be enforced architecturally, not in documentation** (7/9). The `/v1/is_authorized` API accepts an `entities` array unconditionally. The warning at `service-architecture.md:157` is aspirational prose. Fix: partition entities into trusted (PDP-resolved) and untrusted (PEP-supplied hints). Revocable attributes (roles, grants) must come from PDP-owned DB.

4. **Mandatory pre-evaluation schema validation** (7/9). Schneier's novel finding: Cedar skip-on-error means missing entity attributes cause forbid policies to be skipped, letting permits fire. Pre-eval validation must fail the request rather than passing incomplete data to Cedar evaluation.

5. **Sidecar deployment with plugin-side decision cache** (6/9). Sidecar for latency; plugin-side cache for decoupling. Fowler's reframe: the cache buys deployment topology independence, not the topology itself. Hightower conceded sidecar after this argument.

6. **Decision audit logging is required** (5/9). Hashimoto: compliance requires it. Schneier: cannot detect skip-on-error bypass post-incident without it.

### Disagreements

**Cantrill vs Fowler vs DHH: Go plugin vs Lua plugin**

Cantrill initially advocated Lua-first (IPC overhead is 30-500% of Cedar eval cost). Antirez proposed thin Lua shim + thick Rust PDP -- Cantrill fully endorsed this in Round 2 as architecturally correct. Fowler and DHH held Go-first for testability and type safety. Hightower broke the deadlock: neither is universally correct; the architecture must state the latency budget and derive the language choice from it. **Resolution: contested.** Cantrill+Antirez favor thin Lua; Fowler+DHH+Hashimoto favor Go-first-profile-later. Consensus: state the latency SLA, then decide.

**DHH vs Cantrill+Antirez: Cedar vs OPA**

DHH challenged: OPA has existing Kong enterprise plugin, management APIs, decision logging, larger ecosystem. Cedar's 42-81x speed advantage is moot when IPC dominates. Cantrill countered: OPA also runs as a sidecar with HTTP API -- same IPC cost. Cedar wins on tail latency (bounded eval) and CPU footprint. Hashimoto offered the bridge: AuthZen as the external API makes the engine choice reversible. **Resolution: contested but converging.** Cedar is defensible for correctness properties; AuthZen provides the escape valve if OPA ecosystem wins long-term. DHH's "missing scale target" observation is itself a finding -- the architecture has no stated traffic projection.

**Schneier vs AGI-Acc: Fail-closed behavior under saturation**

Schneier: fail-closed is non-negotiable for security events. AGI-Acc: fail-closed under infrastructure saturation (PDP overloaded) means entire agent organization halts simultaneously -- a liveness catastrophe. **Resolution: converging.** Differentiate 403 (policy deny) from 503+Retry-After (PDP unavailable). Fail-closed for security events, 503 with retry semantics for infrastructure saturation.

### Findings

| # | Finding | Sev | Raised By | Status | Detail |
|---|---------|-----|-----------|--------|--------|
| 1 | FailOpen bool is a security trapdoor | P0 | 9/9 panelists | defended | No audit, no alert, no expiry, per-route toggle |
| 2 | Entity trust boundary is enforcement gap | P0 | Schneier, Cantrill, Fowler, Hashimoto | defended | entities array unconditional + JWT roles as authoritative |
| 3 | Skip-on-error creates forbid bypass vector | P0 | Schneier | defended | Missing attribute causes forbid to skip, permit fires |
| 4 | No multi-instance policy consistency model | P0 | Lamport | unchallenged | Rolling reload = contradictory decisions |
| 5 | Revocation window unbounded (30-60s) | P1 | Lamport, Schneier, AGI-Acc | defended | Deny list mentioned but not implemented |
| 6 | No policy CI/CD pipeline | P1 | Hashimoto | unchallenged | Runtime gate, not pre-deploy gate |
| 7 | Decision logging absent | P1 | Hashimoto, Hightower | unchallenged | Metrics exist, audit log does not |
| 8 | Cache key has no policy version | P1 | Lamport, Antirez, Schneier | defended | Stale allows survive policy changes |
| 9 | Cache stampede on TTL boundary | P1 | Antirez | defended | No jitter, no stale-while-revalidate |
| 10 | Admin reload endpoint unauthenticated | P1 | Schneier | unchallenged | Localhost-accessible DoS vector |
| 11 | Batch blocking pool saturation | P1 | AGI-Acc | unchallenged | spawn_blocking pool exhaustion at scale |
| 12 | No delegation attenuation primitive | P1 | AGI-Acc | unchallenged | Cedar cannot express permission subsetting |
| 13 | arc-swap torn-read window | P2 | Lamport -> DHH challenged | conceded | Evaluation path safe; structural fix still recommended |
| 14 | Four reload mechanisms | P2 | DHH | defended | Pick two, drop the rest |

### Tension Point Decisions

| # | Tension | Decision | Confidence | Key Argument |
|---|---------|----------|------------|--------------|
| 1 | Go vs Lua plugin | **State latency budget first, then decide.** Cantrill+Antirez: thin Lua shim if latency-sensitive. Fowler+DHH: Go if development velocity. | Contested | IPC floor cost (0.3-0.5ms) must be weighed against latency SLA |
| 2 | HTTP vs gRPC | **Start with HTTP/JSON.** Curl-debuggable, simpler. gRPC adds proto compilation for marginal gain on localhost. | Moderate (6/9) | Sidecar = localhost; serialization overhead is noise at this scale |
| 3 | Sidecar vs remote | **Sidecar with plugin-side decision cache.** Cache provides deployment topology independence. | Strong (7/9) | Fowler's reframe: cache decouples, not topology |
| 4 | Policy hot-reload | **arc-swap + file watcher.** Single Arc<(PolicySet, Schema)> tuple swap. Add Cache wrapper for hot-path performance. | Strong (7/9) | Correct pattern, needs two fixes (tuple swap + Cache wrapper) |
| 5 | Entity resolution | **Tiered by attribute class.** JWT for non-revocable identity (email, department). PDP-owned DB for revocable attributes (roles, grants). Static hierarchy in ArcSwap. | Strong (7/9) | Schneier: revocable attributes MUST NOT come from JWT |
| 6 | Fail-open vs fail-closed | **Fail-closed with differentiated responses.** 403 for policy deny. 503+Retry-After for PDP unavailability. Emergency override only with audit+alert+time-bound. | Strong (8/9) | AGI-Acc + Schneier convergence: security vs liveness distinction |

### Scores (Panel Averages, Post-Deliberation)

| Dimension | Avg | Range | Notes |
|-----------|-----|-------|-------|
| Security design | 0.39 | 0.35-0.45 | 4 P0 findings. Entity trust + skip-on-error compound. Fail-open trapdoor unanimous. |
| Correctness | 0.58 | 0.45-0.72 | Cedar engine correct. Integration boundaries weak. Multi-instance consistency unspecified. |
| Performance design | 0.55 | 0.45-0.65 | arc-swap correct but missing Cache wrapper. IPC tax acknowledged but not resolved. |
| Operational maturity | 0.45 | 0.35-0.55 | No policy lifecycle. No decision logging. Sidecar lifecycle unspecified. |
| Scope discipline | 0.40 | 0.30-0.50 | Four reload mechanisms, three entity strategies, no stated scale target. |
| Agent-scale readiness | 0.40 | 0.35-0.50 | No delegation model. Batch pool saturation. Cache incoherence at N sidecars. |

### Cross-Model Calibration

GPT calibration panelist was unavailable (Codex CLI MCP not connected in this session). No cross-model delta computed.

### Per-Expert Detail

#### Leslie Lamport (Distributed Systems)
> Multi-instance policy distribution has no consistency invariant (P0). Revocation window is a specification gap, not just implementation (P0). arc-swap torn-read downgraded to P2 after DHH showed Cedar eval doesn't reference Schema. Cache needs epoch versioning.

#### Bryan Cantrill (Systems/Rust)
> Go IPC tax is the wrong trade for a sub-ms engine. Thin Lua + thick Rust PDP is the correct architecture (endorsed Antirez's proposal). Entity trust boundary is aspirational prose, not enforcement. Cache wrapper omission on hot path is a missed optimization.

#### Martin Fowler (System Architect)
> PEP/PDP boundary is undefined -- plugin crosses into entity resolution. Entity tiering rule needed: revocable from DB, non-revocable from JWT. AuthZen on external API, Cedar-native for plugin. Cache-as-decoupling reframes the sidecar debate.

#### Kelsey Hightower (DevOps/SRE)
> Three-tier chain (Kong -> plugin -> PDP -> DB) = four failure domains. Sidecar concern reframed after Fowler's cache argument. Decision logging gap means no on-call runbook for "why is user X getting 403?" Latency budget must drive plugin language choice.

#### Bruce Schneier (Security)
> Fail-open ceremony spec: audit log, security alert, time-bound, per-route only. JWT roles are PEP-supplied but treated as authoritative -- role freshness != signature validity. Skip-on-error is a novel forbid bypass vector requiring mandatory pre-eval schema validation. AuthZen subject.properties is an additional injection surface.

#### Mitchell Hashimoto (Infrastructure Tooling)
> Policy lifecycle is the 80% problem the architecture ignores. No CI/CD pipeline, no decision logging, no sidecar supervision. Cedar's engine is solid; the surrounding infrastructure is absent. Skip-on-error bypass strengthens the case for decision audit logging.

#### Antirez (Simplicity/Data Structures)
> Four hops for a boolean answer. Decision cache not worth it at MVP -- Cedar sub-ms eval means caching saves the smallest component of total latency. Single Arc tuple swap for torn-read fix. Skip decision cache, keep entity cache.

#### DHH (Build-vs-Buy Skeptic)
> Cedar vs OPA business case never made on ecosystem grounds. IPC overhead dwarfs Cedar's speed advantage over OPA. Architecture designed without a scale target -- every component defaults to maximally complex option. Skip-on-error bypass (Schneier) is the sharpest security finding.

#### AGI Accelerationist (Scale/Composability)
> Cedar has no delegation attenuation primitive -- agent spawning sub-agents with scoped permissions requires external entity lifecycle management at spawn rates. Fail-closed under saturation = full agent organization halt. Batch endpoint pool saturation at agent workloads. Sidecar cache incoherence for real-time revocations.

### Actions

| Pri | Action | Raised By | Consensus |
|-----|--------|-----------|-----------|
| P0 | Remove FailOpen bool; implement audit+alert+time-bound emergency override; 503+Retry-After for PDP unavailability | Schneier | 9/9 |
| P0 | Mandatory pre-eval schema validation; validation failure = deny | Schneier | 7/9 |
| P0 | Define PEP/PDP entity trust contract; revocable attributes from PDP-owned DB only | Fowler | 7/9 |
| P0 | Specify multi-instance policy consistency model (epoch versioning or bounded staleness) | Lamport | 5/9 |
| P1 | Add decision audit logging (principal, action, resource, decision, determining policies, timestamp) | Hashimoto | 5/9 |
| P1 | Specify policy CI/CD pipeline (git+webhook default) | Hashimoto | 4/9 |
| P1 | Version decision cache key against policy epoch | Lamport | 5/9 |
| P1 | State latency budget; derive plugin language from budget | Cantrill | 6/9 |
| P1 | Authenticate admin reload endpoint | Schneier | 3/9 |
| P2 | Single Arc<(PolicySet, Schema)> tuple swap | Lamport | 4/9 |
