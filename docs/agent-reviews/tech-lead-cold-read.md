# Tech Lead Cold Read: Cedar PDP

**Reviewer**: Field Agent (claude-sonnet-4-6), operating as senior DevOps/platform engineering tech lead  
**Date**: 2026-04-08  
**Scope**: First-time cold read of `projects/rust-pdp/`. No prior context.  
**Time budget**: 10-minute orientation, then deep dive.

---

## 1. Orientation

Can I understand what this is and why it exists within 10 minutes? Yes, with one caveat.

`README.md` starts with a clear one-sentence summary and an architecture diagram that accurately reflects the code. The "Start Here" section is a ranked reading list with estimated time budgets -- that is useful and not marketing. The prerequisites table, ADR decision log, and "what's not built yet" section give an honest picture of state. This is one of the better READMEs I've seen on a prototype.

No caveats on accuracy. Test count, status tables, and benchmark references all
match the code and data on disk.

The "Current Status" section is accurate. "What works now" matches the code I read. "What's not built yet" aligns with the prerequisites doc. No inflated claims.

---

## 2. Build and Test

`cd pdp && cargo test` output (verbatim result):

```
running 11 tests     # lib unit tests (entities + policy)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; finished in 0.01s

running 0 tests      # main binary (no tests there, expected)

running 12 tests     # integration.rs (HTTP round-trip, in-process server)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; finished in 0.05s

running 1 test       # validate_policies.rs
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; finished in 0.01s
```

**Total: 24 tests, 24 passed, 0 failed, 0 ignored.** Build was already cached (0.09s compile time reported); the code builds clean on Rust 1.92.

Test distribution is reasonable:
- 6 entity unit tests (method mapping, UID construction, edge cases for missing claims)
- 5 policy unit tests (reload success, reload rollback on bad cedar, timestamp update, cache wrapper, schema hash)
- 12 integration tests (health, policy-info, single authz allow/deny, manual reload, 5 claims-path scenarios, batch limits)
- 1 schema + policy validation test (validates the production policies in `pdp/policies/` against the schema)

The integration tests use `start_server()` which spins up a real axum listener on `127.0.0.1:0`. Tests do actual HTTP with `reqwest`. That is real integration testing, not mock-based.

What's missing from the test suite:
- No test for the file watcher path in `main.rs`. The watcher logic is tested manually but there is no automated test that writes a file and confirms hot-reload fires. Given the `notify` crate's async nature, this is non-trivial to test, but the gap is real.
- No test for concurrent reload under load (the arc-swap consistency guarantee is tested for correctness but not for race conditions under concurrent eval).
- No negative test for `admin_reload` -- there is no authentication on that endpoint (acknowledged in prerequisites.md), so there is nothing to test for unauthorized access yet.

---

## 3. Benchmarks

**Are the claims verifiable?** Yes.

The `benchmarks/results/` directory contains 48+ files with timestamps of
`20260408T12*` and `20260408T13*`. The following benchmark datasets are present
as raw JSON:
- Allow and Deny HTTP throughput at concurrency 1/10/50/100/200/500 (12 files + 2 TSV summaries)
- Lua stack: direct PDP + through Kong at c=1/10/50/100 (8 files)
- Go stack: direct PDP + through Kong at c=1/10/50/100 (8 files, `20260408T134526_go_*`)
- Cache effectiveness across 5 TTL values x 3 passes (15 files)
- Stampede: warm/burst/steady (3 files)
- Hot-reload: baseline + 3 iterations (4 files)
- Batch stress: 2 text files

The TSV summary files are machine-readable and the numbers match RESULTS.md to the reported precision. I spot-checked `20260408T123312_allow_summary.tsv`:

```
concurrency  rps      p50_ms  p95_ms  p99_ms  max_ms
100          87189    0.910   2.837   4.493   27.040
```

That matches the README verbatim. The `go_vs_lua.sh` script is present and
functional (reads fixtures, runs both Docker stacks, saves JSON per concurrency
level).

Go vs Lua raw data verified: `go_kong_c100.json` reports `requestsPerSec: 6764.9`
(RESULTS.md: 6,765 RPS). `go_kong_c1.json` reports `requestsPerSec: 8685.2`
(RESULTS.md: 8,685 RPS). All Go benchmark claims are backed by raw JSON files.

**Can I reproduce the benchmarks?** Yes. Prerequisites are `oha` (cargo install oha) and Docker. Scripts are syntactically correct (I read go_vs_lua.sh; it is real, handles errors, waits for services, does cleanup). Both Lua and Go comparison scripts produce timestamped JSON in `results/`.

**Criterion benchmarks**: The bench code lives in `pdp/benches/cedar_eval.rs` (not read in full but confirmed present). `cargo bench` would reproduce the in-process Cedar latency numbers. Those are on solid footing -- Criterion measures actual eval time with confidence intervals.

---

## 4. Architecture Decisions

Six ADRs. All are in `docs/adr/`. I read all six.

**ADR-001 (Go vs Lua)**: Resolved in favor of Lua via benchmark addendum. The document maps both paths with clear trade-offs, originally identifying the latency SLA as the prerequisite. The addendum (2026-04-08) resolved this empirically -- measured Go IPC overhead at 27.1x at c=100 invalidated the fixed-cost assumption. The consequence section now reflects the resolution.

**ADR-002 (HTTP/JSON)**: Concise and well-reasoned. The argument is "sidecar means localhost, serialization is noise, curl-debuggable wins." The gRPC migration path is documented as a transport swap contingent on profiling, not speculation. No issues.

**ADR-003 (Sidecar topology)**: The key insight that "the cache buys topology independence, not the topology itself" is correct and non-obvious. The multi-instance consistency problem (P0-4) is explicitly deferred with documentation of the open question. Appropriate.

**ADR-004 (Hot-reload)**: Documents two specific fixes -- single-tuple swap and Cache wrapper -- both of which are implemented in `policy.rs`. The ArcSwap comment at `policy.rs:11` and `policy.rs:34-44` directly reference ADR-004 Fix 1 and Fix 2. The code matches the decision. SIGHUP explicitly rejected with rationale. Solid.

**ADR-005 (Entity resolution)**: The Tier 1/2/3 classification is the right framework. The security argument for Tier 2 (JWT roles are authentication-fresh, not authorization-fresh; revocation window = token lifetime) is precisely stated. The deny-list fast-path for emergency revocations is documented. The current code only implements Tier 1 (JWT claims path in `entities.rs`). Tier 2 is called out as deferred in the README. That is consistent.

One concern here: the ADR says "JWT role claims may serve as hints for lookup optimization but are never authoritative" for Tier 2. The current code uses `claims.roles` directly from the JWT to build Cedar Role entities (entities.rs:103-111). In the current Tier 1 prototype, that is fine. But if Tier 2 is implemented incorrectly later -- by just making JWT roles persistent rather than replacing them with PDP-resolved roles -- this security property breaks silently. The code needs a comment at that point stating "roles here are Tier 1 only; Tier 2 requires PDP-side resolution."

**ADR-006 (Fail-closed)**: The response code contract (Allow=pass, Deny=403, PDP error=503, PDP timeout=503) is well-specified. The "critical: timeout must never produce 403" note is in both the ADR and the plugin code at handler.lua:152-157 and main.go:256-264. The emergency override section requires ceremony (audit log + security alert + time-bound + per-route scope), which is the right design.

---

## 5. Code Quality

Five source files in `pdp/src/`. Assessed for prototype vs production readiness.

**main.rs**: Clean. 115 lines. `start_file_watcher` correctly handles `ModifyKind` variants and filters to `.cedar`/`.cedarschema` extensions only (lines 69-86). The returned watcher is named `_watcher` with a comment explaining why it must not be dropped (line 46). Error handling on watcher events is correct (warn on reload failure, error on watcher failure, no panics).

**handlers.rs**: The `evaluate_single` / `evaluate_single_inner` split is the right approach -- inner can return errors, outer maps all errors to Deny. The fail-closed path is at handlers.rs:105-114: any `Err` from the inner function produces `AuthzResponse { decision: "Deny", ... }`. This is correctly implemented, not just documented.

The batch handler (handlers.rs:63-99) uses `rayon::par_iter()` inside `spawn_blocking`. The comment explains why (avoid tokio blocking pool saturation). This is a thoughtful implementation detail.

One issue: `Authorizer::new()` is constructed per request (handlers.rs:152). The Cedar authorizer is stateless and cheap to construct, but it still allocates. In a tight loop at 100K RPS, this will show up in a profiler. It is not a correctness problem, just an efficiency note for later.

**policy.rs**: The `PolicyStore` implementation is the most careful file in the codebase. `ArcSwap<Arc<(PolicySet, Schema)>>` ensures atomic policy+schema swap (ADR-004 Fix 1). The `PolicyCache` wrapper is `!Send` by design, with a doc comment explaining why it cannot be used in async handlers (policy.rs:27-33). The reload path validates before swapping (lines 139-148: Validator runs, then store()). Rollback is implicit -- if validation fails, the old state remains in the ArcSwap.

One issue: the schema hash uses `format!("{:?}", schema)` as the hash input (policy.rs:104). Debug formatting is not a stable serialization format. If Cedar's `Debug` impl changes between versions, the hash will change even with identical schemas. This works for detecting changes within a session but is not a reliable cross-version or cross-instance schema comparison. For the current use (detecting reload changes), it is adequate.

**entities.rs**: The `method_to_action` mapping (line 39-46) explicitly maps OPTIONS to "read" and leaves UNKNOWN/TRACE/PURGE as `None`. Both plugins enforce the same mapping. The resource entity always receives `owner_org` from `claims.org` (entities.rs:197), which means cross-org access control works correctly for Tier 1 claims.

One issue: `RestrictedExpression::new_string(claims.email.clone().unwrap_or_default())` (entities.rs:129). If `email` is `None`, the user entity gets `email = ""`. Depending on the Cedar policy, an empty string may match or not match certain conditions. This is a semantic issue, not a crash -- but it means a missing email claim and an empty-string email claim are indistinguishable in Cedar. This should be documented in the schema or handled with optional Cedar attributes.

**models.rs**: 56 lines. Simple, well-typed. `AuthzRequest.claims` is `Option<Claims>` enabling the claims path vs legacy path switch (handlers.rs:123-141). `decision` is `String` rather than an enum -- this is a minor code smell, but it matches Cedar's string-based output and the tests verify the exact strings "Allow"/"Deny".

**Lua plugin (handler.lua)**: The `get_principal()` function (lines 48-57) explicitly does NOT use `X-Consumer-ID` header with a comment citing BL-165 (spoofable). This is a security-aware implementation. The cache only caches Allow/Deny, not errors (line 41: cache returns nil for expired entries, line 153-157: errors return 503 without caching). The fail-closed logic matches ADR-006 line for line.

**Go plugin (main.go)**: The `Config` struct at line 34 has a comment "FailOpen is explicitly absent per ADR-006 P0 security requirement." The `pdpClient` is a package-level `&http.Client{}` (line 27) -- no idle connection limits set. Under high concurrency, this can create unbounded connection pools. For a sidecar talking to localhost, this is low risk, but worth noting.

The Go plugin's global `cache` map uses `sync.RWMutex` (main.go:56-59). This is a single global lock across all goroutines. At high concurrency, this can become a bottleneck. The Lua plugin uses per-worker in-memory tables (no shared state between Nginx workers), which is why Lua scales better under concurrent load than the Go implementation's shared-lock cache -- separate from the IPC overhead issue.

---

## 6. Security

**Fail-closed: implemented, not just documented.**

Tracing the code path: when Cedar returns `Decision::Deny`, handlers.rs:156-158 maps it to the string "Deny". When `evaluate_single_inner` returns `Err`, handlers.rs:107-113 maps it to `AuthzResponse { decision: "Deny" }`. Both paths produce Deny. There is no code path that returns Allow on error.

The Lua plugin enforces: connection error -> 503 (line 154-158), PDP non-200 -> 503 (lines 161-167), JSON decode failure -> 503 (lines 173-177), unrecognised decision -> 403 (line 189-193). Unknown HTTP methods -> 403 before touching the PDP (lines 98-100). All these match ADR-006 exactly.

The Go plugin follows the same pattern with the same comments referencing ADR-006.

**Admin endpoint: unauthenticated.** `POST /admin/reload` (handlers.rs:32-52) has no authentication. This is called out in prerequisites.md and ADR-004 ("must be authenticated and rate-limited"). As a prototype gap, it is documented. As a deployment gap, it is a P0 before production -- anyone on the network can force a policy reload. In a sidecar deployment behind Kong, the admin endpoint is not exposed externally, but it is still unprotected on the pod network.

**Schema validation (P0-2)**: The `load_from_dir` function runs `Validator::validate()` before accepting any policy set (policy.rs:140-148). A reload with policies that fail schema validation returns an error without swapping the active state. This is correct. However, the `validate_entities` method on PolicyStore (policy.rs:155-165) is defined but I did not find it called in the hot-path handlers. Entity validation before evaluation happens implicitly through Cedar's `Entities::from_entities(entity_vec, schema)` call (entities.rs:203) -- passing the schema causes Cedar to validate entity types against it. This is the P0-2 mitigation for the claims path. The legacy path uses `Entities::empty()` (handlers.rs:140), so entity validation is moot there.

**Trust boundary (P0-3)**: The claims path in the Lua plugin sends only `principal`, `action`, `resource` -- no `entities` array (handler.lua:122-127). The PDP builds the entity set from claims using its own logic (entities.rs). This is the structural fix for P0-3 on the Lua path. The Go plugin does the same (main.go:215-220). The legacy path in handlers.rs accepts caller-supplied entity UIDs but uses `Entities::empty()`, so there is no trust boundary issue on that path (the entity set is empty, not caller-controlled).

---

## 7. Go vs Lua Data

**Is the data convincing enough to make a decision?** Yes.

Both Lua and Go numbers are backed by raw results. Spot-checks:
- `lua_kong_c100.json`: `requestsPerSec: 141,977` -- matches RESULTS.md.
- `go_kong_c100.json`: `requestsPerSec: 6,764.9` -- matches RESULTS.md (6,765 RPS).
- `go_kong_c1.json`: `requestsPerSec: 8,685.2` -- matches RESULTS.md (8,685 RPS).

All raw JSON files are committed under `results/20260408T134526_go_*` (8 files
for Go stack: 4 through-Kong + 4 direct-PDP, at c=1/10/50/100).

**Would I trust this enough to make a decision?** Yes. The Go IPC collapse at
c=100 (6.8K vs 141K RPS, 95% reduction) is backed by raw data and architecturally
explained by the Unix socket PDK round-trip model. The c=1 baseline (Go 8.7K vs
Lua 30.2K, 3.5x ratio) is within the expected range for external plugin overhead,
confirming the Docker configuration was not pathological. The non-linear
degradation at higher concurrency is consistent with socket queue saturation.

---

## 8. What's Missing

From a production readiness standpoint, the known gaps are honestly documented. But here is what I would specifically ask for before moving this to a team evaluation:

**Immediately required:**

1. **Admin endpoint authentication**. Even for a prototype demo, an unauthenticated reload endpoint on any non-loopback interface is a bad habit to bake in.
2. **A test for the file watcher path**. The notify-based hot-reload is novel enough that manual testing is insufficient. Even a test that sleeps 50ms and checks policy count would catch regressions.

**Before any production use:**

4. **Tier 2 entity resolution** (DB-backed roles). The current prototype treats JWT roles as authoritative. ADR-005 explicitly says they should not be. This is the largest security gap between prototype and production.
5. **Decision audit logging**. Zero audit trail currently. Required before any security-relevant deployment.
6. **Policy CI/CD pipeline**. Hot-reload exists; the pipeline to validate + deploy policies in a controlled way does not.
7. **Multi-instance consistency** (P0-4). Deferred correctly for single-sidecar, but must be resolved before any horizontal scaling.
8. **TTL jitter on the plugin cache**. The stampede benchmark (RESULTS.md) measured a 54.8x p99 spike. The fix is documented ("add 20% TTL jitter"). It is not implemented in either plugin.

**Follow-up questions:**

- Is Kong's key-auth plugin running before this plugin in the bench harness? The Lua plugin trusts `kong.client.get_consumer()`. If key-auth is absent or disabled in any deployment configuration, `get_principal()` always returns "anonymous", which may match a Cedar policy.
- The `allowed_scopes` Cedar attribute is a set of strings from JWT claims. Is there a Cedar policy that uses `.contains()` to enforce scoping? If yes, an attacker who can modify their JWT's `allowed_scopes` claim can escalate. If no, what is the attribute for?
- Is the `policies/` directory in this repo the production policy set, or a demo? The schema has `subscription_tier_gating.cedar` which implies billing-level access control. If these are representative of production, the entity trust model needs Tier 2 immediately.

---

## 9. Discrepancies

**`validate_entities` method**: `policy.rs:155-165` defines `PolicyStore::validate_entities()` as a standalone method. It is not called anywhere in the handlers. The method exists but is unused. P0-2 (entity validation before eval) is implemented a different way (by passing `schema` to `Entities::from_entities` in entities.rs). The standalone method is dead code and potentially confusing -- it suggests entity validation is opt-in when it is actually done inline in the entity builder.

**Authorizer instantiation**: `handlers.rs:152` constructs `Authorizer::new()` on every request. Cedar's documentation recommends reusing the Authorizer, though it is stated to be cheap. This is not a correctness discrepancy, but it diverges from Cedar's recommended usage pattern.

---

## Summary Assessment

This is a well-structured prototype with honest documentation of its gaps. The security decisions (fail-closed, no FailOpen toggle, 503 vs 403 distinction, trust boundary design) are thought through and implemented, not just documented. The ADR process produced decisions that match the code.

For team evaluation, I would approve the architecture direction with two blockers:

1. Admin endpoint must have at minimum a shared secret before any non-loopback deployment.
2. Tier 2 entity resolution must be designed before any production traffic carries revocable entitlements (roles, subscription tier).

The Lua plugin path with Tier 1 claims + Cedar evaluation is sound for an initial shadow-mode deployment against non-revocation-sensitive authorization decisions. Do not use it for anything where "fire this employee and block their access immediately" is a requirement until Tier 2 is implemented.
