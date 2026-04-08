### Martin Fowler -- Software Architect

> The architecture is conceptually sound but the abstraction boundaries are muddled: the plugin is doing too much entity construction, the AuthZen layer's value is real but undersold, and the fail-open config option is a design smell that will bite you.

#### Findings

| # | Finding | Severity | File:Line | Detail |
|---|---------|----------|-----------|--------|
| 1 | Plugin crosses PEP boundary into entity resolution | P1 | `kong-plugin-architecture.md:93-108` | The PDK methods available (headers, consumer, credential) suggest the plugin will construct entity representations to pass to the PDP. `rust-pdp-service-architecture.md:157` explicitly warns "PDP should NOT trust entity data from PEP for security-critical attributes" -- yet the only alternative shown requires the PDP to do DB lookup per-request. This creates an unclear contract: which attributes are the plugin's responsibility vs the PDP's? Clean PEP should pass principal ID and request context only; the PDP resolves everything else. The current design leaves this boundary undefined. |
| 2 | `fail_open` as a plugin config field is a P1 design smell | P1 | `kong-plugin-architecture.md:68` | `FailOpen bool` in the plugin Config struct means fail-open behavior is a per-route operator decision. Security decisions should not have a toggle; fail-closed must be the only production path. The architecture doc (`rust-pdp-service-architecture.md:222`) correctly states "Never fail-open unless explicitly configured" -- but explicitly configured should mean a deliberate engineering decision documented in ADRs, not a per-route JSON field. If timeout handling is the concern, the right answer is circuit-breaker semantics with a tight SLA, not a flag that invites misconfiguration. |
| 3 | HTTP-to-gRPC migration path is reversible only if the plugin abstraction holds | P2 | `kong-plugin-architecture.md:175-181` | The decision matrix correctly starts with Go+HTTP. Migration to gRPC is feasible precisely because the Go plugin encapsulates the transport. However, migration to Lua (Option C) is NOT similarly encapsulated -- it requires replacing the plugin entirely and losing the Unix socket IPC model. The architecture should state clearly that Lua migration is a plugin rewrite, not a transport swap, so teams don't assume it's equivalent in effort. |
| 4 | AuthZen endpoint design is correct but the rationale is incomplete | P2 | `rust-pdp-service-architecture.md:83-84` | "Allows engine-swapping without PEP changes" is the right framing, but it undersells the other half: AuthZen also enables PEP-swapping without PDP changes. If you later replace Kong with another gateway, the PDP doesn't change. The bidirectional decoupling is the architectural value. The current framing may lead teams to deprioritize it as "just OPA compatibility." |
| 5 | Entity resolution strategy has an unresolved tension between JWT-only and DB lookup | P1 | `entitlement-translation.md:168-173`, `rust-pdp-service-architecture.md:153-158` | The docs offer three patterns (JWT-only, DB lookup, cached hierarchy) but don't establish which attributes belong to which tier. In practice this will be decided ad hoc per-feature, creating an inconsistent entity model. The architecture needs a decision rule: what class of attributes can come from JWT (performance, acceptable staleness), what must come from DB (authoritative, revocable), and what lives in the static hierarchy cache. Without this rule, the system will grow inconsistently. |

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Separation of concerns (PEP/PDP boundary) | 0.55 | Plugin responsibilities are undefined; entity construction boundary is implicit rather than explicit |
| Evolutionary architecture (reversibility) | 0.70 | HTTP->gRPC is reversible; sidecar->remote requires config changes but is feasible; Lua migration is incorrectly presented as equivalent to gRPC migration |
| Abstraction quality (AuthZen layer) | 0.75 | AuthZen choice is correct and well-placed; rationale is thin and may lead to it being skipped |
| Fail-safe defaults | 0.60 | Fail-closed default is correct; fail_open config field is a design smell that partially negates the default |
| Entity resolution design | 0.50 | Three patterns offered with no decision rule; will produce inconsistent implementations |

#### Assessment

The foundational choices here are sound. Cedar over OPA is well-reasoned (the performance data is real, and the formal verification story is architecturally relevant -- not just a marketing point). The axum+tonic stack is idiomatic Rust. The arc-swap hot-reload pattern is elegant: validation-before-swap at `rust-pdp-service-architecture.md:111` is exactly right, and lock-free reads matter for a PDP that is on the critical path of every request.

What concerns me is the PEP/PDP boundary. In the classic authorization model, the PEP (Kong plugin) enforces decisions but does not interpret them; the PDP makes decisions but does not enforce them; and a third component (the entity store) resolves identity. The architecture diagram in `rust-pdp-service-architecture.md:226-251` correctly shows three boxes below the PDP (PolicyStore, EntityCache, EntityDB) but doesn't show how entity data flows from Kong into the PDP. The `kong-plugin-architecture.md` section on JWT claims (`lines 113-117`) describes three different ways the plugin might get identity attributes. This ambiguity will produce implementations where the plugin assembles partial entities from JWTs and the PDP assembles partial entities from DB lookups, with no canonical definition of what's authoritative where.

The `fail_open` field in the Config struct (`kong-plugin-architecture.md:68`) is the most immediately actionable issue. A field like this -- present in a per-route configuration -- will be enabled by an operator under performance pressure, during an incident, "just temporarily," and then never reverted. If fail-open behavior is ever legitimate, it should require an explicit security exception process, not a config toggle. The right architectural answer is a bounded timeout with a circuit breaker that sheds load gracefully, not a soft bypass.

The AuthZen vs Cedar-native question: implement both, in the right direction. Cedar-native for the Kong plugin (it's an internal interface, performance matters), AuthZen on the external surface (for future gateway portability and standards compliance). The architecture document inverts this by saying "implement AuthZen on external API" which is correct, but then doesn't say which endpoint the Kong plugin uses. That needs to be explicit.

Before this ships, I want to see: (1) a written decision rule for entity attribute tiers (JWT vs DB vs hierarchy cache), (2) `fail_open` removed from the plugin config struct with a documented circuit-breaker alternative, and (3) explicit documentation that the Kong plugin calls the Cedar-native endpoint, not the AuthZen endpoint.

#### Deliberation Addendum

**Positions revised**:
- F2 (`fail_open` config field) upgraded from P1 to P0. Lamport's argument was decisive: a network partition between Kong and a remote PDP triggers this flag simultaneously across all routes -- a predictable failure mode, not an edge case. The finding is further compounded by the absence of any circuit-breaker state machine in the architecture (Lamport's distinct second observation). Both issues must be addressed.
- F1 (PEP/PDP boundary) sharpened by Schneier: the boundary is not merely undefined, it is defined incorrectly in the Cedarling pattern (`entitlement-translation.md:129-148`), which constructs role memberships from JWT claims. Role membership is a revocable security-critical attribute. JWT signature validity is authentication freshness, not authorization freshness. The tiering rule must be explicit: revocable entitlements (roles, grants, permissions) must come from PDP-owned DB resolution; JWT claims may supply non-revocable identity attributes only.

**Positions reinforced**:
- F3 (entity resolution has no decision rule) survived challenge from all panelists. Hightower reframed it as a hidden availability coupling; Lamport reframed it as a revocation window problem. Both are consequences of the same gap. The finding holds from three independent angles and no panelist disagreed.
- F4 (AuthZen rationale incomplete) was unchallenged. AuthZen enables bidirectional decoupling -- both engine-swappable and PEP-swappable. The current framing only sells one direction and may lead teams to deprioritize the endpoint.
- My position on Go vs Lua (against Cantrill's "start with Lua" prescription): held. The right frame is measuring the actual latency budget first. Go's maintainability advantages are not offset by 0.3ms of IPC overhead for most deployments.

**New observations from deliberation**:
- Schneier's skip-on-error/forbid bypass: `cedar-policy-language.md:50-51` skip-on-error semantics mean a `forbid` policy that errors due to a missing entity attribute is skipped, allowing a `permit` to fire. This is a real attack surface I missed entirely. Mitigation requires mandatory pre-evaluation schema validation that fails the request rather than the forbid evaluation. This should be a required implementation pattern in the architecture.
- Cantrill's structural proof that the `entities` array in the PDP API (`rust-pdp-service-architecture.md:43-61`) is unconditionally accepted confirms that the line-157 warning is aspirational, not enforced. The API needs to partition entities into trusted (PDP-resolved) and untrusted (PEP-supplied hints), not rely on prose guidance.
- Hightower's sidecar coupling: the lifecycle coupling (Cedar policy update = Kong pod operation) is real, but the architectural lever is the plugin-side decision cache, not deployment topology. Sidecar vs remote is reversible if the cache exists; without the cache, neither topology is operationally sound.

**Score changes**:
- Fail-safe defaults: 0.60 -> 0.40. `fail_open` is P0, not P1, and the absent circuit-breaker state machine is a second distinct gap. The PDP's correct default-deny is undermined at two layers above it.
- Separation of concerns (PEP/PDP boundary): 0.55 -> 0.45. The Cedarling pattern is an incorrect boundary definition, not merely an undefined one -- a more severe finding than initially scored.
