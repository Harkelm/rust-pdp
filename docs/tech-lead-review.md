# Tech Lead Review: Cedar PDP Prototype

Reviewer: incoming tech lead, cold read
Date: 2026-04-08

---

## 1. Orientation Experience

The README is genuinely good. The "10 minutes / 30 minutes" tiered reading guide
is useful -- I followed it and landed in the right places. The ASCII architecture
diagram is accurate. The project structure table matches what is actually on disk.
The "what works / what is not built" section at the bottom is honest and I did not
find anything it falsely claims to have built.

One friction point: the README says "read ADR-006, then ADR-005, then the rest."
That order makes sense intellectually but ADR-002 references an AuthZen endpoint
(`/access/v1/evaluation`) that is never mentioned again in the codebase -- it does
not exist in `src/main.rs` or `src/handlers.rs`. A new reader following the ADRs
sequentially will expect to find it. See the Discrepancies section below.

Overall orientation: easy. I was productive within ten minutes of starting.

---

## 2. Build and Test Results

### `cargo test` -- 16 tests, all pass

Ran without any configuration. Output:

```
10 unit tests (entities + policy)
5 integration tests (HTTP against a real embedded server)
1 schema/policy validation test
```

All 16 pass. No flakiness observed.

The tests are meaningful, not just smoke. Specific examples of quality coverage:

- `reload_rejects_invalid_cedar_keeps_previous` (`policy.rs:195`) verifies the
  safety property of arc-swap: a broken policy file cannot evict a working one.
  This is the most important invariant of the hot-reload design and it has a test.

- `test_jwt_with_roles_produces_user_with_role_parents` (`entities.rs:252`) makes
  concrete assertions about the entity parent hierarchy, not just "does it return
  something."

- `test_permit_decision` and `test_deny_decision` (`tests/integration.rs:84,109`)
  exercise the HTTP layer end-to-end and check both status code and Cedar
  diagnostics fields.

What is missing from the test suite: there are no tests for the claims path in
`handlers.rs`. The `is_authorized` handler has two branches -- the legacy
direct-UID path and the claims path (`if let Some(claims) = &req.claims`). The
five integration tests only exercise the legacy path (they pass raw Cedar entity
UIDs). The claims path -- which is the production path -- has zero integration
coverage.

### `cargo bench` -- all 9 benchmarks complete

The benchmark matrix (3 policy counts x 3 entity counts) runs cleanly. Results on
this machine (i7-14700KF, release build):

| Policies | Entities | Mean     |
|----------|----------|----------|
| 10       | 10       | 5.23 us  |
| 10       | 100      | 5.28 us  |
| 10       | 1000     | 5.27 us  |
| 100      | 10       | 45.4 us  |
| 100      | 100      | 45.4 us  |
| 100      | 1000     | 45.9 us  |
| 1000     | 10       | 446 us   |
| 1000     | 100      | 445 us   |
| 1000     | 1000     | 447 us   |

These numbers match the pre-recorded results in `benchmarks/RESULTS.md` within
noise. The entity-count-does-not-matter finding is confirmed and interesting --
Cedar's entity representation clearly does not scan the set.

One limitation of the benchmarks worth noting: they measure a single-match
scenario (request always matches exactly one policy, no attribute conditions). The
production policies (`policies/`) include attribute comparisons (`principal.suspended`,
`principal.allowed_scopes.contains(...)`). Attribute evaluation has additional cost
not captured here. The benchmarks are honest about this (no false claims) but the
gap should be quantified before treating the numbers as production estimates.

### Go plugin -- builds and tests pass

`go build .` succeeds silently. `go test ./...` passes all tests in 0.2s.

The test quality is notable: `TestConfigHasNoFailOpenField` (`main_test.go:78`)
uses reflection to assert that no `fail_open`-tagged field exists in the Config
struct. This is a security property test, not just a functional one. Good.

The limitation: `Access()` calls `kong.Response.Exit()` and `kong.Log.*`, which
require the Kong PDK. The test file works around this by testing the HTTP client
logic separately via `callPDPForTest()` rather than calling `Access()` directly.
This is the right tradeoff given PDK dependencies, but it means `Access()` itself
is not unit-tested -- the tests validate the logic but not its wiring into the PDK
call sites. An integration test against a real Kong instance is the only way to
close that gap.

### Docker integration tests -- reviewable but not run

The setup in `tests/integration/` is clean and I can follow it without running it:

- `docker-compose.yml` wires three services: real Cedar PDP (built from source),
  httpbin as upstream, Kong 3.9 with the Lua plugin mounted as a volume.
- A `pdp-503` service (a trivial Python HTTP server that always returns 503)
  simulates PDP overload without mocking. This is a good approach -- it tests the
  actual HTTP client behavior.
- The timeout test uses a non-routable IP (`10.255.255.1`) to force a real timeout.
  This is reliable on most networks but is an assumption worth noting.
- `run_tests.sh` covers six cases: Allow, Deny, no-auth 401, PDP timeout, PDP 503,
  and Cedar default-deny for unknown principal. That is a reasonable set for an
  integration harness.

One structural concern: all three service-level plugins (`cedar-pdp` on
test-route, timeout-route, and overload-route) share the same plugin name in
`kong.yml`. This is valid Kong declarative config but some Kong versions handle
multiple same-name plugin instances per route differently. I would want to verify
this works on the exact Kong 3.9 image before claiming the tests are definitively
green.

### Lua plugin tests -- not runnable without busted

`spec/handler_spec.lua` requires the `busted` test framework. It is not in the
repo. The file is well-written and the mocking strategy is sound (PDK and
`resty.http` are injected via `package.preload` / `_G.kong`, so no real Kong is
needed). But I cannot run these tests without installing `busted` via LuaRocks,
which is not documented in the README's prerequisites.

---

## 3. Discrepancies Between Docs and Code

These are concrete gaps between what the documentation says and what is
implemented.

**ADR-002 references an AuthZen endpoint that does not exist.**
ADR-002 states: "The PDP exposes two API surfaces: Cedar-native (`/v1/is_authorized`)
for the Kong plugin, AuthZen (`/access/v1/evaluation`) for external consumers."
The implemented routes in `src/main.rs` are `/v1/is_authorized`, `/v1/policy-info`,
`/admin/reload`, and `/health`. No AuthZen endpoint. The ADR marks this as a
"Consequence" rather than an immediate deliverable, so this may be intentional
deferral, but the ADR reads as if it exists now. The README should clarify whether
AuthZen is deferred.

**ADR-004 specifies an arc-swap `Cache` wrapper that is not used.**
ADR-004 says: "Fix 2: Cache wrapper on hot path. `ArcSwap::load()` touches the
global reference count epoch on every call. `Cache::load()` maintains a
thread-local copy refreshed lazily... the Cache wrapper provides 10-25x speedup on
the hot path. The current design omits it." The current code in `policy.rs` still
uses `ArcSwap::load()` directly on every `is_authorized` call. The ADR acknowledges
this was a known gap ("the current design omits it") but notes it as a fix. It is
not fixed in the current code. For a sidecar at any meaningful request volume, this
matters.

**ADR-003 says the plugin-side decision cache is mandatory before deployment.
Neither plugin has one.**
ADR-003: "The plugin-side decision cache is the prerequisite that makes topology
secondary... Plugin must implement a decision cache before deployment (not
optional)." Neither `handler.lua` nor `main.go` has any decision caching. The
README's "not built yet" list does not mention this. This is a production blocker
per the project's own criteria that is not surfaced in the current status summary.

**The integration test policies use a different schema namespace than the
production policies.**
`pdp/policies/api.cedarschema` uses no namespace (`entity User`, `entity Role`,
`entity ApiResource`). The production policies in `policies/` use the `ApiGateway`
namespace (`ApiGateway::User`, `ApiGateway::Role`, `ApiGateway::ApiResource`).
The integration tests in `tests/integration.rs` send raw UIDs like
`User::"alice"` and `Action::"ViewResource"` which match the no-namespace
schema -- they would fail against the production schema. This is intentional
test isolation (the crate has its own `pdp/policies/` separate from the
project-level `policies/`), but it is confusing on first read and means the
integration tests do not exercise the production schema at all.

**`validate_entities()` is defined but not used on the hot path.**
`policy.rs:117` defines `validate_entities()` for P0-2 mitigation. The `is_authorized`
handler does not call it. For the claims path, validation is delegated to
`build_entities(..., Some(schema))` at `handlers.rs:73` -- which does pass the
schema to `Entities::from_entities()`. This is functionally equivalent (schema
validation happens in the claims path) but `validate_entities()` is dead code. The
legacy path (`handlers.rs:78-81`) skips validation entirely -- `Entities::empty()`
is passed to the authorizer, so there is nothing to validate. The comment at
line 94 says "schema validation on request is optional." The P0-2 concern applies
to the legacy path only when entities are supplied; since the legacy path uses an
empty entity set, the security concern does not apply there. This is fine but worth
documenting more explicitly -- the "legacy path is safe because it sends no
entities" is not stated anywhere in the code comments.

---

## 4. Code Quality Observations

Generally clean. A few specific notes:

**`policy.rs:69` -- schema hash via `format!("{:?}", schema)`.** The schema hash
is computed from the Debug representation of the Cedar Schema type. This is
fragile: if the Debug output changes across Cedar versions (struct field reordering,
formatting changes), the hash changes even when the schema content did not. For a
hash used to detect schema changes across reloads, this is acceptable. For a hash
intended to identify schema versions across deployments or instances, it is not.
The current use case (detecting when a reload changed the schema) is fine, but
the hash should not be used for cross-instance policy epoch comparison without
replacing this with a content-derived hash (e.g., hash of the raw schema source
bytes).

**`entities.rs:181-187` -- resource attributes are hardcoded defaults.** The
`ApiResource` entity always has `classification = "internal"` and `department = ""`
regardless of what the actual route is. For the data-scope-read policy
(`data_scope_access.cedar:14`) to function -- `principal.allowed_scopes.contains(resource.classification)` --
the classification must come from the actual resource, not a default. This means
the `data_scope_access` policy in `policies/` evaluates against a constant
"internal" for every request. The only way to get a different classification is
through Tier 2 entity resolution (not implemented). The code works for the test
fixtures but is not usable for the full policy set as written.

**`main.go:168` -- `http.Client{}` is created per-request.** In the Go plugin,
a new `http.Client` is created on every call to `Access()`. HTTP clients in Go
maintain a connection pool. Creating one per request throws away keep-alive
connections and forces a new TCP handshake on every authorization callout. For a
sidecar on localhost this adds ~100-200 us per request unnecessarily. The client
should be constructed once in `New()` or a package-level var.

**`handlers.rs:84-88` -- context deserialization path.** The `Context::from_json_value`
call passes `None` for the schema, meaning context values are not schema-validated.
If a Cedar policy condition references a context attribute that is absent or
wrong-typed, Cedar's skip-on-error semantics apply. For `permit` conditions this
is a false deny (acceptable behavior). For a `forbid` condition referencing context,
it would be a false allow. The production policies in `policies/` do not use context
attributes currently, so this is not an active risk -- but it will become one when
context-based policies are added, and there is no guard against it.

---

## 5. Completeness Against Original Ask

The original ask was: "basic architecture, request/context model, performance
implications, and key risks."

**Basic architecture**: Yes. The PDP service architecture is implemented and
documented (ADRs 001-006). The Kong plugin PEP is implemented in both Lua and Go.
The separation of concerns (thin PEP, thick PDP) is consistently applied. The
roundtable deliberation record in `docs/roundtable/` shows the reasoning behind
the decisions.

**Request/context model**: Partially. The request model (`models.rs`) is clear.
The entity resolution model (`entities.rs`) implements Tier 1 (JWT claims). Tier 2
(DB-backed roles) and Tier 3 (static hierarchy) from ADR-005 are specified but
not implemented. The context field in the request model is present but schema-
unvalidated and not used by any current production policy.

**Performance implications**: Yes. Cedar evaluation benchmarks are measured and
documented in `benchmarks/RESULTS.md`. HTTP round-trip latency is measured. The
Go plugin IPC cost is documented in ADR-001. The analysis is honest and the
numbers are reproducible (I ran the benchmarks myself and got matching results).
The benchmark gap I noted (no attribute-condition scenarios) is the main missing
piece.

**Key risks**: Yes. `docs/risk-analysis-and-migration-plan.md` covers eight risks
with severity, likelihood, impact, mitigation, and status for each. The framing
is accurate and the open items are correctly identified as blockers.

---

## 6. Follow-Up Questions for the Author

1. **What is the p99 latency SLA?** ADR-001 says the language decision is blocked
   on this. The benchmarks claim the 5ms budget is met with margin. But 5ms is
   called "conservative" without citing a measured baseline for the existing auth
   path. What is the actual latency budget, and does it account for the Go IPC
   floor cost (0.3-0.5ms) if the Go plugin path is chosen?

2. **What does the existing entitlement data model look like?** The Tier 2 entity
   resolution scope (5-10 engineering days in the estimate) is the primary schedule
   driver. Before committing to that range, I need to understand: is role membership
   in a relational DB, an LDAP directory, a proprietary IAM service? What are the
   read latency characteristics? Does the PDP need to cache or can it query per-
   request?

3. **What does the legacy authorization layer look like?** The migration plan
   references "the existing authorization layer" throughout but never describes it.
   What is it? OPA? Custom middleware? A database lookup? Understanding the existing
   behavior is required to write the Cedar policies that match it -- which is the
   core Phase 1 risk.

4. **Is there a policy corpus from the existing system?** The production policies
   in `policies/` are clearly illustrative (RBAC routes, org scoping, subscription
   tiers, data scopes). A real migration requires translating the existing policy
   logic into Cedar. How many policies are there? Are they documented or do they
   live in code?

5. **Who owns the Cedar schema and policy files?** ADR-004 specifies a policy CI/CD
   pipeline but does not say which team owns the policy repository. If it is the
   security team, they need to be onboarded to Cedar syntax and the schema design.
   If it is the platform team, there is an ownership question for security-critical
   policies.

6. **What Kong version and deployment model are we targeting?** The integration test
   uses Kong 3.9 DB-less mode. The production Kong version may be different. Kong's
   Lua sandbox restrictions and available libraries vary by version. The plugin uses
   `resty.http` and `cjson.safe` -- are these available in the production Kong
   environment?

7. **What is the plan for the ADR-001 decision?** Two plugins exist but neither
   will be used for production without resolving this. The Go plugin has the `http.Client`
   per-request bug. The Lua plugin has no runnable test instructions in the README.
   Is there a decision timeline or does it depend on the latency SLA answer?

8. **Are there concurrent users or routes that already need ABAC (attribute-based)
   decisions?** The schema supports org-scoped access and data classification
   policies, but those require Tier 2 entity resolution. If any current routes
   require these policies, shadow mode is blocked until Tier 2 is built.

---

## 7. What I Would Run in My Own Environment

In priority order:

1. **The Docker integration tests end-to-end.** I want to see T1-T6 in
   `run_tests.sh` pass against a real Kong 3.9 + real PDP. In particular I want to
   verify T4 (timeout -> 503 + Retry-After) and T5 (PDP 503 -> 503 forwarded) with
   actual headers, not just status codes. The `check_header` function in the test
   script warns but does not fail on missing headers.

2. **The HTTP load test under concurrency.** `benchmarks/http_load_test.sh` is
   sequential (one request at a time). I would run it with parallel workers (e.g.,
   via `xargs -P 20`) to see what happens to p99 latency and error rate under
   concurrent load. The arc-swap implementation should handle this cleanly, but I
   want to verify.

3. **A hot-reload test under concurrent load.** Start the PDP serving traffic,
   modify a policy file, observe the file watcher trigger, verify in-flight requests
   are not interrupted. The `reload_rejects_invalid_cedar_keeps_previous` unit test
   covers the single-threaded case. I want the concurrent case.

4. **The Go plugin in a real Kong pod.** The `callPDPForTest` workaround in
   `main_test.go` is the right approach for unit tests, but `Access()` has never
   been called against a real PDK. I want to run the T1-T6 scenarios with the Go
   plugin enabled instead of the Lua plugin to verify the behavior is identical.

5. **The Lua plugin busted tests.** Once `busted` is installed, I want to run
   `spec/handler_spec.lua` and verify all tests pass. The mock design looks correct
   but I cannot confirm without running it.

6. **Cedar policy evaluation with real attribute conditions.** The benchmarks use
   attribute-free entities. I want to benchmark `suspended_account_deny.cedar` and
   `data_scope_access.cedar` with entities that have all required attributes set.
   The forbid policy evaluation path (which involves attribute reads) may have
   different performance characteristics than the pure RBAC benchmarks.

---

## 8. Summary Assessment

This is a solid prototype that delivers what was asked: a functioning Cedar PDP
wired into Kong, with a clear architecture, measured performance, and an honest
risk analysis. The code is readable, the tests are meaningful, and the ADRs provide
enough context to understand why decisions were made.

The main issues to address before Phase 1 work begins:

- The plugin-side decision cache is missing and is documented as mandatory (ADR-003).
  This needs to be in scope for Phase 1, not a later phase.
- The arc-swap `Cache` wrapper is not implemented (ADR-004 Fix 2). Low effort, high
  impact for any production request volume.
- The Go plugin creates a new `http.Client` per request. Fix before any load testing.
- The claims integration path has no HTTP-level test coverage. Add this before
  treating the 16-passing-test count as meaningful coverage.
- The `enforcement_mode` shadow toggle is described in the migration plan but not
  implemented in either plugin. It is a Phase 1 prerequisite for safe rollout.
- Lua plugin test instructions (`busted` installation) are missing from the README.

None of these are architectural problems -- they are implementation gaps that are
straightforward to close. The foundation (Cedar evaluation, schema design, entity
model, failure mode handling, hot-reload) is sound.
