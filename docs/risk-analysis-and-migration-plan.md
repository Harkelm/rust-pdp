# Risk Analysis and Migration Plan: Cedar PDP for API Authorization

## Executive Summary

This document covers the risk profile and migration strategy for replacing Kong's
existing authorization layer with a Cedar-based Policy Decision Point (PDP). Cedar
evaluation performance is validated (5-445 us depending on policy count, well under
the 5ms budget) and the core PDP is implemented with integration tests passing.
Recommendation: proceed to shadow mode with three open items resolved first --
Tier 2 entity resolution (DB-backed roles), decision audit logging, and admin
endpoint authentication.

---

## 1. Key Risks

### Risk 1: Skip-on-Error Bypass in Forbid Policies (P0-2)

- **Severity**: Critical
- **Likelihood**: Medium (requires attacker-controlled entity data)
- **Impact**: Cedar skips policies that error during evaluation. A `forbid` policy
  referencing a missing entity attribute is silently dropped, allowing `permit`
  policies to fire. An attacker who can inject or omit entity attributes can
  selectively nullify forbid rules.
- **Mitigation**: Pre-evaluation schema validation in `validate_entities()` before
  calling `is_authorized()`. Validation failure returns deny (not pass-through).
  Policy authoring rule: all attributes referenced in `forbid` conditions must be
  marked required (not `?`) in the Cedar schema. This must be enforced as a CI
  gate on the policy repository.
- **Status**: Partially addressed. `validate_entities()` is implemented. CI gate
  on the policy repository is not yet implemented.

### Risk 2: Fail-Open Config Toggle (P0-1)

- **Severity**: Critical
- **Likelihood**: Low (toggle removed per ADR-006)
- **Impact**: If fail-open were configurable at runtime, any PDP disruption silently
  bypasses authorization with no audit trail, no alerting, and no time bound.
- **Mitigation**: `FailOpen bool` removed from plugin Config struct. PDP unavailability
  returns 503+Retry-After to the client. Emergency fail-open requires a deployment
  change with mandatory audit log entry, security team alert, and automatic
  time-bound expiry (ADR-006).
- **Status**: Addressed.

### Risk 3: PEP/PDP Entity Trust Contract (P0-3)

- **Severity**: High
- **Likelihood**: Medium (depends on plugin language choice)
- **Impact**: If the Kong plugin can inject arbitrary entity data into the PDP
  request, a compromised plugin (or misconfigured routing) can supply entity
  attributes that elevate privileges.
- **Mitigation**: ADR-005 tiered resolution. If thin Lua plugin (ADR-001 Path A)
  is chosen, the plugin sends only principal ID + request context -- entity trust
  boundary is structural (plugin cannot inject entity data). If Go plugin (Path B),
  the PDP API must partition trusted (PDP-resolved) vs untrusted (PEP-supplied)
  entity channels at the API level. The AuthZen endpoint's `subject.properties`
  field must be a validation boundary, not a pass-through.
- **Status**: Addressed for Path A. Requires explicit API enforcement for Path B.
  ADR-001 plugin language decision is still contested -- resolution unblocks this.

### Risk 4: Multi-Instance Policy Consistency (P0-4)

- **Severity**: High
- **Likelihood**: Low for sidecar MVP, High if multi-pod scaling occurs without
  addressing this prerequisite
- **Impact**: Multiple PDP instances (or replicas) can hold different active policy
  sets during rolling reload. Two concurrent requests hitting different instances
  can receive contradictory decisions. This is undetectable without epoch tracking.
- **Mitigation**: For MVP sidecar deployment, single-instance-per-pod is a hard
  constraint. Multi-pod or remote deployment requires one of: epoch-based
  versioning (decisions carry policy epoch), activation barrier (global coordination
  on swap), or explicit eventual consistency with stated maximum staleness bound.
  The constraint must be documented and enforced operationally.
- **Status**: Open. Not required for initial sidecar deployment. Must be resolved
  before remote deployment or multi-pod scaling.

### Risk 5: Tier 2 Entity Resolution Not Implemented

- **Severity**: High
- **Likelihood**: High (it is explicitly not built yet)
- **Impact**: Role memberships, permission grants, and subscription tiers are
  currently resolved from JWT claims. A JWT issued before a role revocation carries
  wrong entitlements for the full token lifetime (minutes to hours). Terminated
  employee or compromised account may retain access until token expiry.
- **Mitigation**: Implement PDP-owned DB for Tier 2 attributes (ADR-005). Add
  emergency revocation deny list checked before Cedar evaluation for bounded
  revocation latency independent of cache TTL. Until Tier 2 is implemented, the
  system should not be used for enforcement on routes where role revocation
  freshness is a security requirement.
- **Status**: Open. Blocks promotion beyond shadow mode for role-sensitive routes.

### Risk 6: No Decision Audit Logging

- **Severity**: High
- **Likelihood**: High (it is explicitly not built yet)
- **Impact**: No record of what Cedar decided, for whom, under which policy version.
  Cannot detect when fail-open was active during a security incident. Cannot replay
  decisions for compliance or post-incident analysis. ADR-006 explicitly lists this
  as a consequence requirement.
- **Mitigation**: Implement structured decision logging: timestamp, principal,
  action, resource, policy epoch, Cedar decision (allow/deny), determining policies.
  Emit to append-only store (structured log file or audit table). Separate from
  request logs -- decision records must be tamper-evident and retained per
  compliance policy.
- **Status**: Open. Blocks production deployment.

### Risk 7: Admin Endpoint Authentication

- **Severity**: Medium
- **Likelihood**: Medium (network-accessible endpoint, no auth)
- **Impact**: `POST /admin/reload` is unauthenticated. Any process with network
  access to the PDP can trigger policy reload, enabling a denial-of-service by
  reload flooding or a policy injection attack if the policy directory is writable.
- **Mitigation**: Authenticate the admin endpoint (shared secret, mutual TLS, or
  network policy restricting access to Kong pod only). Rate-limit reload requests.
  For sidecar deployment, network policy restricting to localhost is an acceptable
  interim measure.
- **Status**: Open. Acceptable for sidecar MVP with localhost network restriction.

### Risk 8: Policy CI/CD Pipeline Absent

- **Severity**: Medium
- **Likelihood**: High (no pipeline exists yet)
- **Impact**: Policy changes deployed without validation can introduce logic errors
  or schema violations. Without staging, a broken policy set reaches production.
  Cedar's arc-swap validates before swap (broken files never become active), but
  this does not catch semantic errors -- a valid policy file with wrong logic.
- **Mitigation**: Implement git-backed policy repository with CI pipeline: lint
  (Cedar schema validation) + semantic tests (Cedar formal analysis for safety
  properties) + staging deployment + promotion gate. ADR-004 specifies this as a
  prerequisite for production deployment.
- **Status**: Open. Blocks production deployment.

---

## 2. Shadow Mode Deployment Strategy

Shadow mode runs Cedar alongside the existing authorization layer. The existing
layer enforces decisions; Cedar evaluates in parallel and logs results. No traffic
is affected.

### Configuration

Add `enforcement_mode` to the Kong plugin config:

- `legacy`: Existing auth only. Cedar not invoked.
- `shadow`: Both evaluate. Legacy enforces. Cedar result logged with comparison.
- `cedar`: Cedar enforces. Legacy may run in reversed shadow (for regression
  detection during cutover).

This is a runtime config change, not a deployment change.

### Decision Comparison Logging

For every request in shadow mode, log:

```
{
  "ts": "<iso8601>",
  "request_id": "<kong_request_id>",
  "principal": "<user_id>",
  "action": "<http_method>:<path>",
  "legacy_decision": "allow|deny",
  "cedar_decision": "allow|deny",
  "cedar_policy_epoch": "<epoch>",
  "cedar_determining_policies": ["<policy_id>", ...],
  "entity_snapshot_hash": "<sha256>",
  "divergence": true|false
}
```

Route divergence records to a separate stream for triage. Do not mix with
normal request logs -- divergence records drive parity analysis.

### Parity Threshold

Do not proceed to canary cutover until the divergence rate is below 0.1% for
at least 7 days of shadow traffic on the target routes. Every divergence must
be triaged and categorized:

- `policy_gap`: Cedar policy is missing coverage
- `over_permission`: Cedar allows what legacy denies (higher priority fix)
- `under_permission`: Cedar denies what legacy allows
- `data_mismatch`: Entity attribute mismatch between systems
- `timing`: Race condition or TTL difference

### What to Validate Before Shadow Mode

Before enabling shadow mode, verify:

1. `validate_entities()` is active on all requests (P0-2 mitigation running)
2. Tier 1 JWT-to-entity mapping covers all attributes referenced by policies
3. Decision logging is writing to the divergence stream
4. Cedar evaluation does not add more than 2ms to p99 request latency under
   production load (this is a conservative floor -- benchmarks suggest <0.5ms)

---

## 3. Rollback Procedure

The `enforcement_mode` config flag enables zero-downtime rollback at any phase.

### Immediate Rollback (< 1 minute)

1. Update Kong plugin config: set `enforcement_mode` to `shadow` (from `cedar`)
   or `legacy` (from `shadow`).
2. Kong reloads config without pod restart.
3. Cedar continues running but stops enforcing. No traffic impact.

### Full Revert (removes Cedar from the path)

1. Set `enforcement_mode = "legacy"`.
2. Verify error rates return to baseline in monitoring (allow 2-minute window).
3. If a Cedar bug caused data corruption (not expected -- Cedar is read-only on
   auth decisions), escalate to incident response separately.

### Rollback Triggers

Initiate immediate rollback if any of the following occur:

- Cedar error rate exceeds 1% of requests on enforced routes
- p99 authorization latency exceeds 5ms (baseline: <0.5ms)
- Divergence rate exceeds 1% after Cedar enforcement is enabled (indicates
  policy gap not caught in shadow mode)
- Any `over_permission` divergence after Cedar enforcement (Cedar allows more
  than legacy -- security regression)
- PDP process crash rate exceeds zero per hour (sidecar supervision must page)

### After Rollback

1. File an incident record with: timestamp, enforcement_mode at time of rollback,
   error/divergence samples, Cedar policy epoch active at the time.
2. Do not re-enable Cedar enforcement until root cause is identified and a
   regression test is added to the policy CI pipeline.

---

## 4. Phased Rollout Plan

### Phase 1: Foundation Completion

**Scope**: Resolve all open prerequisites before any production traffic sees Cedar.

**Work items**:
- Implement Tier 2 entity resolution (DB-backed roles/entitlements)
- Implement decision audit logging (structured, append-only)
- Authenticate admin reload endpoint
- Implement `enforcement_mode` config toggle in Kong plugin
- Implement policy CI/CD pipeline (git -> Cedar schema validation -> staging ->
  production promotion gate)
- Resolve ADR-001 plugin language decision (Lua Path A vs Go Path B)
- Document single-instance-per-pod as a hard operational constraint (P0-4
  mitigation for MVP)

**Entry criteria**: Core PDP integration tests pass (6/6 currently passing).

**Exit criteria**:
- All open risk items above are either Addressed or explicitly deferred with
  documented constraints
- Decision audit log is writing to storage and queryable
- Policy CI pipeline is running on the policy repository
- Enforcement mode toggle is deployed and tested in a staging environment

**Duration**: 2-3 sprints depending on Tier 2 entity resolution complexity.

### Phase 2: Shadow Mode (No Traffic Impact)

**Scope**: Enable Cedar in shadow mode on a single low-risk internal service route.
Cedar evaluates but does not enforce.

**Entry criteria**:
- Phase 1 exit criteria met
- Staging parity validated (Cedar and legacy agree on all staging test cases)
- Divergence logging stream is active and being reviewed

**Work during this phase**:
- Monitor divergence stream daily
- Triage all divergences within 1 business day
- Add regression tests for each triaged divergence to policy CI pipeline

**Exit criteria**:
- Shadow mode running for minimum 7 days on the target route
- Divergence rate below 0.1% for the final 7 days
- Zero unresolved `over_permission` divergences
- Decision audit log covering 100% of shadow-mode requests

**Duration**: 1-3 weeks depending on divergence volume.

### Phase 3: Canary Enforcement (1-5% of Routes)

**Scope**: Enable Cedar enforcement on the lowest-risk routes first (read-only
endpoints, non-critical paths). Maintain rollback readiness throughout.

**Entry criteria**: Phase 2 exit criteria met.

**Work during this phase**:
- Begin with a single read-only route (e.g., `GET /api/v1/health` or equivalent
  non-sensitive endpoint)
- Monitor Cedar error rate, latency p99, and divergence rate on enforced routes
- Weekly review of decision audit log for anomalies
- Keep legacy in reversed shadow mode (evaluates but does not enforce) for
  regression detection

**Exit criteria**:
- Cedar enforcing on target routes for 14 days with no rollback events
- Cedar p99 latency on enforced routes under 2ms (well under 5ms budget)
- Zero security regressions (over_permission divergences while Cedar enforcing)
- Legacy reversed-shadow divergence rate below 0.01% (legacy and Cedar agree)

**Duration**: 2-4 weeks.

### Phase 4: Full Enforcement

**Scope**: Expand Cedar enforcement to all routes. Deprecate legacy auth path.

**Entry criteria**: Phase 3 exit criteria met for all planned route groups.

**Work during this phase**:
- Migrate routes in groups by risk tier (low-risk -> medium -> high-risk /
  write operations / admin paths)
- Each route group goes through a 7-day enforcement window before the next group
- Legacy path remains available until all routes are confirmed stable

**Exit criteria**:
- Cedar enforcing on all routes for 30 days without rollback
- Legacy auth path removed from config (or documented as deprecated with a
  removal date)
- Policy CI/CD pipeline covering 100% of policy changes
- Decision audit retention policy documented and operational

**Duration**: 4-8 weeks depending on route count and risk classification.

---

## 5. Monitoring and Alerting Requirements

### Required Metrics

| Metric | Source | Alert Threshold |
|--------|--------|----------------|
| Cedar error rate | PDP /metrics or structured logs | > 0.1% of requests |
| Cedar p99 latency | PDP /metrics histogram | > 2ms |
| PDP process health | Kong sidecar supervision | Any crash |
| Policy epoch | PDP admin or /metrics | Unexpected rollback |
| Decision divergence rate | Shadow mode log stream | > 0.1% |
| Over-permission divergences | Shadow/reversed shadow stream | > 0 (page immediately) |
| `validate_entities()` rejection rate | PDP structured log | > 0.01% (investigate) |

### Decision Audit Logging (Required for Production)

Every Cedar authorization decision must be logged with:

- `request_id` -- correlatable with Kong access log
- `ts` -- ISO 8601 timestamp
- `principal_uid` -- Cedar entity UID of the requester
- `action` -- Cedar action UID
- `resource_uid` -- Cedar resource UID
- `decision` -- `Allow` or `Deny`
- `policy_epoch` -- version identifier of the active policy set at decision time
- `determining_policies` -- array of policy IDs that produced the decision
  (Cedar diagnostics provides this)
- `enforcement_mode` -- `shadow`, `cedar` (documents the mode at decision time)

Logs must be:
- Written to an append-only store separate from request logs
- Retained for the organization's compliance retention period
- Accessible for replay: given a `request_id`, reconstruct what Cedar decided and
  why, using the `policy_epoch` to retrieve the policy set active at that time

### Policy Hot-Reload Monitoring

- Log every reload trigger (file watcher or admin endpoint): timestamp, trigger
  source, policy epoch before/after, validation outcome
- Alert if reload fails validation (broken policy file pushed -- the arc-swap
  prevents it from activating, but the failure is operationally significant)
- Alert if the active policy epoch diverges across pods (relevant when multi-pod
  deployment is enabled, requires P0-4 solution)

### Sidecar Supervision

The PDP runs as a sidecar in the Kong pod. A PDP crash is currently undetectable
unless wired into Kong's health check:

- Wire PDP `/health` into Kong pod readiness probe
- Configure supervision (systemd or container restart policy) with a maximum
  restart budget and alerting on repeated crashes
- PDP crash must page on-call, not silently restart

---

## 6. Effort Estimates

Estimates are in engineer-days. Ranges reflect uncertainty in Tier 2 entity
resolution scope, which depends on the existing entitlement data model.

### Phase 1: Foundation Completion

| Work Item | Estimate |
|-----------|----------|
| Tier 2 entity resolution (DB-backed roles) | 5-10 days |
| Decision audit logging implementation | 2-3 days |
| Admin endpoint authentication | 1 day |
| Enforcement mode toggle in Kong plugin | 1-2 days |
| Policy CI/CD pipeline | 3-5 days |
| ADR-001 plugin language decision + any rework | 1-3 days |
| P0-4 documentation and operational constraint | 0.5 days |
| **Phase 1 total** | **13-24 days** |

### Phase 2: Shadow Mode

| Work Item | Estimate |
|-----------|----------|
| Shadow mode enablement and verification | 0.5 days |
| Divergence triage and policy fixes (ongoing) | 2-5 days |
| Regression test additions to policy CI | 1-2 days |
| **Phase 2 total** | **3-7 days** (plus 7-21 calendar days observation) |

### Phase 3: Canary Enforcement

| Work Item | Estimate |
|-----------|----------|
| Canary route selection and enablement | 0.5 days |
| Monitoring dashboard and alert wiring | 1-2 days |
| Incident response runbook for rollback | 0.5 days |
| Bug fixes from canary traffic (contingency) | 2-5 days |
| **Phase 3 total** | **4-8 days** (plus 14-28 calendar days observation) |

### Phase 4: Full Enforcement

| Work Item | Estimate |
|-----------|----------|
| Route group migration (per group) | 0.5-1 day each |
| Legacy auth path deprecation and removal | 1-2 days |
| Compliance documentation (audit retention) | 1 day |
| **Phase 4 total** | **variable by route count + 3 days overhead** |

### Total Estimate

| Phase | Engineering Days | Calendar Window |
|-------|-----------------|----------------|
| Phase 1: Foundation | 13-24 | 3-6 weeks |
| Phase 2: Shadow | 3-7 | 2-5 weeks |
| Phase 3: Canary | 4-8 | 3-6 weeks |
| Phase 4: Full | variable | 4-8 weeks |
| **Total** | **20-39 + route migration** | **12-25 weeks** |

The primary schedule driver is Phase 1 Tier 2 entity resolution. If the existing
entitlement model maps cleanly to Cedar entities, the lower bound applies. If it
requires schema redesign or sync infrastructure, the upper bound applies. That
scoping should be done before committing to a Phase 1 timeline.
