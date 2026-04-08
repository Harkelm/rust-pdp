### Mitchell Hashimoto -- Infrastructure Tooling Creator

> Policy-as-code is not a feature, it's a lifecycle. This architecture nails the engine but treats the pipeline as someone else's problem.

**Persona note**: No persona file at `.claude/skills/roundtable/references/personas/hashimoto.md`. Lens constructed from known public record: creator of Vagrant, Terraform, Consul, Vault, Packer, Nomad, and Sentinel (HashiCorp's policy engine). Deep background in developer experience, service mesh (Consul Connect), secrets management (Vault), and policy-as-code (Sentinel). Communication style: pragmatic, infrastructure-first, developer workflow obsession, strong opinions on operational maturity.

---

#### Findings

| # | Finding | Severity | File:Line | Detail |
|---|---------|----------|-----------|--------|
| 1 | No policy CI/CD pipeline defined | P1 | `rust-pdp-service-architecture.md:136-143` | The policy store patterns table lists four storage backends (file-based, DB, S3, Git+watcher) but none specifies a CI/CD pipeline. Who validates policies before they land in production? The arc-swap hot-reload pattern (`PolicyStore::reload` at line 108-115) validates before swap -- good -- but that's a runtime gate, not a pre-deploy gate. Sentinel has lint + plan + apply + enforce. Cedar has none of this here. |
| 2 | Fail-open is a config flag with no guardrails | P0 | `kong-plugin-architecture.md:68` | `fail_open: bool` in the Go plugin `Config` struct. A single boolean config field controls whether the gateway fails open on PDP timeout. No audit trail when this is enabled, no alerting, no time limit. In Vault, enabling dangerous features requires `seal` operations and audit logging. Here, ops can silently flip this in a plugin config and open the blast door. This is a security-critical config that needs ceremony. |
| 3 | JWT claims extraction is a design gap, not a solved problem | P1 | `kong-plugin-architecture.md:113-118` | JWT claims are listed as "NOT directly available through PDK" with three options enumerated but none recommended as the default. This is the primary entity identity signal (sub -> principal, roles -> parents), yet the architecture defers the decision. The entitlement-translation.md Cedarling pattern (`entitlement-translation.md:122-151`) gives a complete JWT-to-Cedar mapping -- but the Kong plugin doc doesn't reference it. These two documents aren't connected. |
| 4 | Go plugin vs Lua plugin decision is premature performance anxiety | P2 | `kong-plugin-architecture.md:173-182` | The decision matrix recommends starting with Go + HTTP (Option A) with a note to "migrate to Lua if IPC overhead matters." This migration path is painful: Lua plugins run in-process but can't use connection pools cleanly, debug story is weaker, and you lose the Go type system. The 0.3-0.5ms IPC overhead is real but irrelevant for most API authorization use cases where Cedar + entity resolution dominate. The recommendation should commit to Go and only revisit Lua if profiling shows IPC as the actual bottleneck. |
| 5 | Sidecar deployment recommendation is under-specified | P1 | `kong-plugin-architecture.md:165-169` | "Sidecar deployment for localhost networking + co-located lifecycle" is the recommendation, but the operational consequences are not worked through. In Consul Connect, the sidecar lifecycle is a solved problem: health checks, supervision, restart policies, drain on upgrade. Here, "tied to gateway lifecycle" in the deployment table is listed as a feature. It's not -- if the PDP crashes, does Kong route traffic? fail-open? What's the supervision story? |
| 6 | No decision logging architecture | P1 | `rust-pdp-service-architecture.md:201-210` | The observability section (`pdp_decisions_total`, `pdp_evaluation_duration_seconds_bucket`) gives Prometheus metrics but no decision audit log. Sentinel logs every policy decision with principal, policy, outcome, and timestamp. Cedar's `response.diagnostics().reason()` returns determining policy IDs but there's no architecture for persisting these. For compliance use cases (the primary driver for a policy engine at an API gateway), decision logs are table stakes. |

---

#### Scores

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Policy lifecycle maturity | 0.35 | Engine is solid; lifecycle (authoring, testing, staging, production promotion) is absent. No CI/CD, no shadow mode reference in the Kong integration layer, no rollback story at the plugin level. |
| Developer experience | 0.60 | Go plugin pattern is well-specified. JWT extraction gap and the missing connection between entitlement-translation and the Kong plugin are friction points. The `fail_open` footgun is a DX anti-pattern -- easy to misconfigure, hard to audit. |
| Operational maturity | 0.50 | Prometheus metrics are good. Health endpoints are correct. Sidecar lifecycle is unspecified. Decision logging is absent. Policy reload has no notification/event emission that downstream operators can subscribe to. |
| Infrastructure design | 0.65 | arc-swap + validation-before-swap is the right pattern. axum + tonic serving both HTTP and gRPC on one port is pragmatic. The AuthZen interoperability endpoint is forward-thinking. The four-backend policy store table is a useful decision surface. |
| Security design | 0.55 | Default-deny on errors is correct (`rust-pdp-service-architecture.md:216-220`). Entity trust model (PDP resolves authoritative data, PEP provides hints) at line 157-159 is exactly right. The `fail_open` boolean without ceremony is the primary security design gap. |

---

#### Assessment

The Cedar engine selection is defensible. The benchmarks cited (42-81x faster than OPA, sub-millisecond for typical policy sets) are real, and the formal verification story (Lean proofs, bounded evaluation) is genuinely differentiated. When I look at this through the lens of what made Sentinel successful inside HashiCorp's product suite, the engine is only 20% of the problem. The other 80% is the policy lifecycle.

Sentinel has a clear path: write in Sentinel language, `sentinel apply` locally, push to a Sentinel registry, policies are versioned, teams review in PRs, and enforcement is tied to a Terraform Cloud workspace. A developer knows exactly how to get a new policy live and how to roll it back. Cedar has none of this here. The architecture document lists four storage backends -- file-based, database, S3, Git+file-watcher -- as equally valid options without specifying which one enables a real CI/CD pipeline. Git+webhook is the only one that does, and it should be the default recommendation with the others as escape valves.

The sidecar deployment recommendation mirrors Consul Connect's proxy model but without the operational scaffolding that made Consul Connect work. In Consul, every sidecar proxy has: a health check that gates traffic, a registration with the catalog, a drain signal on upgrade, and a supervision mechanism (usually systemd or a container runtime). The Kong+PDP sidecar here has none of that specified. "Tied to gateway lifecycle" is listed as a property in the deployment table as if it's neutral -- it's not. Co-location means a PDP crash is a Kong incident. The supervision and failure mode need to be explicit before this pattern is recommended.

The `fail_open: bool` config flag is the single thing I'd push back hardest on before this ships. In Vault, enabling audit device bypass or disabling a seal type requires deliberate ceremony -- it's not a config boolean. A `fail_open: true` in a Kong plugin config that's applied at the route level can silently disable authorization for a specific API path with no audit event. This needs at minimum: an audit log entry when fail-open fires, an alert threshold (X% of requests failing open in Y seconds triggers an alarm), and ideally a time-boxed fail-open with automatic reversion. The current design makes it easy to accidentally leave authorization disabled.

Before this ships, I want to see: (1) a policy CI/CD pipeline spec -- even a simple git repo + webhook trigger + staging validation step; (2) decision logging architecture with retention and compliance query patterns; (3) explicit sidecar lifecycle management spec; (4) `fail_open` hardened with audit trail and alerting.

---

#### Deliberation Addendum

**Positions revised**:
- F6 (entity trust boundary, originally filed as F3/JWT extraction gap) upgraded from P1 to P0. Originally framed as a documentation gap ("principle without a schema"). Cantrill's analysis of the unconditional `entities` array acceptance in the API spec (`rust-pdp-service-architecture.md:43-61`), combined with Schneier's skip-on-error finding (`cedar-policy-language.md:50-51`), makes this a compound enforcement gap: the API accepts attacker-controlled entity data, Cedar silently drops erroring forbid policies, net result is an active bypass path. Not a documentation omission.
- Security design score: 0.55 -> 0.35. Schneier's skip-on-error forbid bypass is a material finding I missed entirely. Combined with the entity trust enforcement gap, the security design is weaker than my initial read.

**Positions reinforced**:
- fail_open P0 (reinforced by Fowler, Cantrill, Schneier independently -- unchallenged by anyone). The missing `pdp_failopen_total` metric is the crux: silence is the failure mode, not the toggle itself. Fix: mandatory audit log entry on every fail-open request, alert threshold on fail-open rate, time-boxed with automatic reversion.
- Policy CI/CD absence P1 (unchallenged). Runtime validation-before-swap is not a pre-deploy gate. Git+webhook with staging validation is the correct default.
- Decision logging absence P1 (unchallenged, strengthened by Schneier's skip-on-error finding -- you cannot detect the forbid bypass after the fact without a decision audit log).
- Go-first over Lua-first (challenged by Cantrill, held). IPC math is correct; testability regression from Lua is a real cost. Go-first with evidence-driven migration is the right recommendation.
- 503 over 403 for fail-closed behavior (converged with Fowler): when the PDP is unreachable, Kong should return 503 (service unavailable), not 403 (unauthorized). 403 asserts a known authorization decision; 503 is honest about system state and gives the client retry semantics.

**New observations**:
- Schneier's skip-on-error forbid bypass (`cedar-policy-language.md:50-51`) is the most operationally dangerous finding raised by any panelist. Pre-evaluation schema validation -- enforce that all required attributes are present, reject the request if not -- is the fix. The `cedar-policy` crate supports this via `Entities::from_entities([entity], Some(&schema))` but whether it's enforced at the request boundary is unspecified.
- The entity trust gap, JWT role authority (Schneier F2), and skip-on-error bypass (Schneier F3) all root in one underlying missing artifact: a formal contract between PEP and PDP specifying which entity attributes are authoritative (PDP resolves from its own store) vs advisory (accepted from PEP request body). One contract document closes all three findings simultaneously.

**Score changes**:
- Security design: 0.55 -> 0.35 (skip-on-error bypass is a genuine attack surface; entity trust boundary is an enforcement gap not a doc gap)
- Policy lifecycle maturity: 0.35 (held)
- Infrastructure design: 0.65 (held -- arc-swap + axum/tonic remain well-designed; gaps are in surrounding lifecycle, not the core runtime)
