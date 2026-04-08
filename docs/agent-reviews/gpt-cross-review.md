# GPT Cross-Model Review -- Cedar PDP Project

Date: 2026-04-08
Reviewer: Field Agent (claude-sonnet-4-6)
Requested: GPT cross-review via Codex CLI MCP (`mcp__codex-cli__codex`)

## GPT Review Status: UNAVAILABLE

The Codex CLI MCP server (`mcp__codex-cli__codex`) is listed as a deferred tool
in the session manifest but its schema cannot be fetched from ToolSearch. The server
is not operational in this session. No GPT review was obtained.

This document contains a thorough first-party review covering all five requested
dimensions. It is attributed to this Field Agent session, not to GPT. The review
covers the same code that would have been sent to GPT: `handlers.rs`, `policy.rs`,
`entities.rs`, `models.rs`, `kong-plugin-go/main.go`, `kong-plugin-lua/handler.lua`,
and `benchmarks/RESULTS.md`.

---

## Review: Security

### Fail-Closed Implementation

Fail-closed is correctly implemented throughout the stack.

In `handlers.rs`, `evaluate_single` maps all error paths to `Deny`:

```rust
Err(msg) => AuthzResponse {
    decision: "Deny".to_string(),
    ...
}
```

Entity UID parse failures, context parse failures, request construction failures,
and Cedar evaluation errors all produce Deny. There is no code path that returns
Allow on error.

In both plugins, the error handling follows the same pattern: PDP timeout -> 503,
PDP non-200 -> 503, JSON decode failure -> 503. There is no path that produces
an Allow on failure. The comments are explicit: "CRITICAL: timeout must never
produce 403" (because 403 on a transient PDP error would deny legitimate requests).
This is the correct reasoning -- 503+Retry-After is the right failure mode.

**No fail-open vulnerability found.**

### Principal Spoofing Vectors

Both plugins explicitly reject the `X-Consumer-ID` header as a principal source,
using `kong.client.get_consumer()` / `kong.Client.GetConsumer()` instead (BL-165).
This is correct -- the consumer object is set by auth plugins upstream and is not
client-controllable.

The Go plugin falls back to `"anonymous"` when no consumer is set, without error.
This means unauthenticated requests get principal `ApiGateway::User::"anonymous"`.
Whether this is a vulnerability depends on policy content: if no policy permits
`anonymous`, Cedar returns Deny, which is correct. If a policy accidentally permits
`anonymous`, that is a policy authoring problem, not a plugin bug. The plugin
behavior is defensible.

One observation: the Go plugin creates `http.Client{}` as a package-level variable
with no connection pooling configuration (no `Transport` with `MaxIdleConns` etc.).
The default `http.Transport` does pool connections, so this is not a correctness
issue, but the absence of explicit timeout on the client level means the per-request
context timeout is the only guard. This is fine given `ctx, cancel := context.WithTimeout`
is used per request.

**No principal spoofing vector found.**

### Cedar Skip-on-Error Exploitation

The claims path in `evaluate_single_inner` calls `build_entities` and `build_request_uids`.
Both return errors mapped to Deny. There is no path where a malformed claim causes
evaluation to skip and default to Allow.

The legacy path (no `claims` field) uses `Entities::empty()` which means Cedar
evaluates against an empty entity store. Whether that allows or denies depends on
the policy -- a policy using `principal in Role::"admin"` would deny (no entities to
traverse), which is safe. A policy written as `permit(principal, action, resource)`
(unconditional) would allow, but that is the policy author's intent.

**No skip-on-error exploitation path found.**

### Minor Security Observation

`schema_hash` in `policy.rs` is computed as `format!("{:?}", schema)` -- the Debug
representation of the Cedar Schema type. This is fragile: it depends on the Debug
output being stable across cedar-policy versions. If the Debug impl changes, the hash
changes without a schema change, and vice versa. For a correctness indicator this is
acceptable, but it should not be used as a security boundary. Current usage (health
endpoint, informational) is fine.

---

## Review: Correctness

### Batch Endpoint: rayon vs spawn_blocking

The batch endpoint wraps a `rayon::par_iter` inside a single `tokio::task::spawn_blocking`
call. This is correct.

The alternative -- one `spawn_blocking` per sub-request -- would saturate Tokio's
blocking thread pool (default 512 threads) under load and create unnecessary scheduling
overhead. The chosen approach crosses the async/sync boundary once per batch, then
uses rayon's work-stealing thread pool (which is CPU-core-sized) for the parallel
evaluation. This is the right pattern for CPU-bound work within an async handler.

One subtle correctness point: `Arc::clone(&state)` is called to move `policy_state`
into the closure. The closure captures it by move. The rayon threads all share the
same `Arc<(PolicySet, Schema)>`, which is immutable once loaded. This is safe --
`PolicySet` and `Schema` are read-only during evaluation.

**Batch parallelism implementation is correct.**

### arc-swap Hot-Reload

`PolicyStore` uses `ArcSwap<(PolicySet, Schema)>` to store the policy state as a
single atomic pointer to a `(PolicySet, Schema)` tuple. This means a reload is an
atomic pointer swap -- readers either see the old state or the new state, never a
partially-updated state (e.g., new policies with old schema). This is correct and
was noted as "single tuple swap per ADR-004 Fix 1".

The `reload()` method: loads new state from disk, validates it, then calls
`self.state.store(Arc::new(...))`. The store is atomic. In-flight requests holding
a guard from a previous `load()` continue safely because the old Arc is kept alive
by their guard. New requests after the store see the new state.

`PolicyCache` (the thread-local cache wrapper) is documented as `!Send` and is
explicitly excluded from async handlers. The doc comment is accurate. The async
handlers use `PolicyStore::load()` directly, which is the correct path.

**arc-swap usage is correct. No race conditions found.**

### Potential Correctness Issue: schema_hash not updated atomically with state

In `reload()`:
```rust
self.state.store(Arc::new((policy_set, schema)));
self.schema_hash.store(Arc::new(hash));
self.last_reload_epoch_ms.store(now_epoch_ms(), Ordering::Relaxed);
```

These are three separate stores. A reader could observe the new `state` but the old
`schema_hash` if it reads between the first and second store. This is a TOCTOU on
the informational metadata -- the `schema_hash` endpoint could transiently return a
stale hash. The policy evaluation itself is unaffected (it reads only `state`).
Given `schema_hash` is informational only, this is low severity. If it becomes a
correctness dependency, the hash should be embedded in the PolicyState tuple.

### Entity Build: owner_org sourced from claims.org

In `entities.rs`, `ApiResource.owner_org` is set to `claims.org`. This means all
resources are owned by the requesting user's org. In a multi-tenant policy, a rule
like `resource.owner_org == principal.org` would always be true for any same-org
request, regardless of which resource is actually being accessed. This is a policy
modeling concern, not a code bug, but it limits the expressiveness of resource
ownership policies. A production deployment would need resource ownership to come
from a service-side lookup, not from the requester's JWT.

---

## Review: Performance Claims

### In-Process Cedar Evaluation (Criterion)

The numbers are internally consistent and plausible:

- 10 policies at ~5 us, 100 at ~45 us, 1000 at ~444 us shows near-linear scaling.
  Cedar evaluates policies sequentially per its documentation. This matches.
- Entity count having negligible effect is consistent with Cedar's hash-based entity
  store. Entity lookup is O(1) per UID; the number of entities does not increase
  the evaluation scan.
- The realistic policy benchmarks (9-15 us per complex policy) vs trivial (5 us) is
  plausible -- attribute checks and set membership add overhead over pure equality.
- The "realistic + noise" scaling (835 us at 1010 policies) being ~1.9x the trivial
  (445 us at 1000 policies) is consistent with the per-policy overhead being higher
  for complex predicates.

**In-process benchmark numbers are plausible. No red flags.**

### HTTP Round-Trip

P50 of 0.225 ms for localhost curl is plausible for a Tokio/Axum server on the same
machine. The claim that HTTP overhead (~220 us) dominates Cedar evaluation (~5 us)
at low policy counts is accurate given the numbers.

The concurrent throughput numbers (23K RPS at c=1, 105K at c=10, plateauing around
80-220K at higher concurrency) are plausible for a Tokio async server on a 20-core
machine. The Deny path being 2-2.5x faster than Allow at high concurrency is
consistent with Cedar short-circuiting on no matching permit.

The hot-reload p99 spike (+102%, RPS -53%) is plausible given the reload requires
a filesystem scan, string concatenation, Cedar parse, and schema validation -- all
holding the CPU while the rayon pool is also active. No dropped requests is correct
given arc-swap's wait-free read path.

**HTTP benchmark numbers are internally consistent and plausible.**

### Cache Stampede

The 54.8x p99 increase at stampede is alarming but plausible given the scenario:
1000 concurrent requests all hitting a cold cache simultaneously. The recommendation
of 20% TTL jitter is standard and correct.

One gap: the cache in the Go plugin is a package-level map with a coarse mutex
(`sync.RWMutex`). Under high concurrency, multiple goroutines may simultaneously
find a cache miss for the same key and all issue PDP calls (thundering herd). The
current implementation does not have a singleflight mechanism. This is the mechanism
behind the 149 ms p99 at stampede. TTL jitter reduces the number of simultaneous
expirations but does not prevent the thundering herd for any single key that expires
under concurrent load.

---

## Review: Go vs Lua IPC Overhead

### Architectural Explanation for 96% RPS Deficit at c=100

The numbers (Lua: 141K RPS, Go: 5.2K RPS at c=100) are striking. The Go plugin's
regression is architecturally explainable.

Kong's Go external plugin protocol routes each request through a Unix socket (or
named pipe) to a separate Go process. For every incoming request, Kong must:
1. Serialize the PDK call arguments to MessagePack
2. Send them over the socket to the Go process
3. Wait for the Go process to respond
4. Deserialize the response

Each PDK call (GetConsumer, GetMethod, GetPath, Response.Exit) is a separate round
trip over this socket. The Go plugin in this code makes approximately 3-5 PDK calls
per request on the hot path (GetConsumer, GetMethod, GetPath, plus Response.Exit on
deny). That is 3-5 Unix socket round trips per authorization decision.

At c=100, this creates head-of-line blocking: the Go plugin server processes PDK
calls serially per connection, and goroutines pile up waiting for socket I/O.

The Lua plugin runs in-process within the OpenResty/Kong worker. `kong.client.get_consumer()`,
`kong.request.get_method()`, `kong.request.get_path()` are direct in-process Lua/C
calls with no serialization or socket I/O. The only network call is the HTTP request
to the PDP sidecar, which both plugins share.

The performance gap is thus: Lua has 1 network call per request (PDP HTTP). Go has
1 network call (PDP HTTP) + 3-5 socket round trips (PDK IPC). At low concurrency
the IPC latency is masked; at c=100 it saturates the Go plugin server's socket queue.

The literature estimate of -25% IPC overhead was likely derived from simple Go
plugins with 1-2 PDK calls. The cedar plugin's 3-5 PDK calls per request amplifies
the overhead non-linearly under concurrency.

**The 96% RPS deficit is architecturally explainable. The Go plugin is not suitable
for high-concurrency Kong deployments with this many PDK calls per request.**

---

## Review: Production Readiness Gaps

### P0 -- Must Fix Before Production

1. **No JWT signature verification.** The `Claims` struct in `entities.rs` is
   deserialized from the request body directly. There is no verification that the
   JWT is valid, not expired, or signed by a trusted issuer. In the Kong deployment,
   the assumption is that Kong's JWT plugin runs upstream and has already verified
   the token, passing only the consumer ID via `kong.client.get_consumer()`. But the
   PDP's `/v1/is_authorized` endpoint accepts a raw `claims` field in the JSON body
   with no authentication. Any caller who can reach the PDP can supply arbitrary
   claims. The PDP must either (a) be network-isolated to trust only Kong, or (b)
   verify the JWT independently.

2. **No authentication on the admin reload endpoint.** `POST /v1/reload` triggers
   a policy reload from disk. There is no authentication on this endpoint. Any
   network-reachable caller can trigger a reload. In a sidecar deployment, this is
   mitigated if the PDP is not exposed externally. But it should be explicitly
   secured.

3. **Cache stampede under production load.** The Go plugin cache has no singleflight
   protection. Measured 54.8x p99 spike at TTL boundary. TTL jitter recommended in
   RESULTS.md but not yet implemented.

4. **`owner_org` from requester JWT.** As noted above, resource ownership policies
   that use `resource.owner_org` are trivially satisfied by a same-org user for any
   resource. A production deployment needs resource ownership from a service-side
   source, not the requester's claims.

### P1 -- Should Fix Before Wide Rollout

5. **No rate limiting on PDP.** The batch endpoint accepts up to 100 sub-requests.
   There is no per-caller rate limiting. A single client can issue sustained batch
   requests and saturate the rayon pool.

6. **Policy directory trust.** `PolicyStore::from_dir` reads all `.cedar` and
   `.cedarschema` files from a directory. If the directory is writable by non-root
   processes, an attacker with local access could inject policies. Deployment must
   ensure the policy directory is owned by the PDP process user and not world-writable.

7. **`schema_hash` via Debug format.** Should be replaced with a stable serialization
   (e.g., hash the raw schema source text before parsing) to ensure the hash is
   reproducible and version-stable.

8. **Go plugin not viable at scale.** The benchmark results make this clear. The
   Go plugin should be deprecated in favor of the Lua plugin for production. The ADR
   should be updated to reflect the measured data, not the literature estimate.

### P2 -- Hardening for Production

9. **No structured logging.** `tracing::info!` is used but there is no log
   correlation (request ID, principal, decision) that would enable audit trail
   reconstruction. A production PDP needs every decision logged with principal,
   action, resource, decision, policy IDs that matched, and request correlation ID.

10. **No metrics.** No Prometheus/OpenTelemetry instrumentation. Latency histograms,
    decision counters (Allow/Deny by policy), and cache hit rates are needed for
    operational observability.

11. **Reload failure alerting.** If `PolicyStore::reload()` fails (e.g., policy file
    corrupted mid-deploy), the PDP silently continues on the old policy set. There is
    no metric or alert for reload failure. An operator deploying a new policy version
    would have no immediate signal that the deployment failed.

---

## Synthesis: Actionable vs Noise

### Actionable (act on before production)

| Finding | Severity | File | Action |
|---------|----------|------|--------|
| PDP `/v1/is_authorized` accepts unauthenticated claims | P0 | handlers.rs | Network isolation or JWT verification |
| Admin reload endpoint unauthenticated | P0 | handlers.rs, main.rs | Add auth middleware or bind to loopback only |
| Cache stampede: no singleflight | P0 | kong-plugin-go/main.go | Add singleflight or TTL jitter |
| owner_org from requester JWT | P0 | entities.rs | Service-side resource ownership lookup |
| Go plugin not viable at c>10 | P1 | kong-plugin-go/main.go | Deprecate, use Lua plugin |
| schema_hash via Debug format | P1 | policy.rs | Hash source text instead |
| No audit log per decision | P2 | handlers.rs | Add structured decision log |
| No metrics | P2 | handlers.rs | Add Prometheus instrumentation |

### Noise (low priority or acceptable as-is)

- `http.Client{}` with default transport in Go plugin: acceptable, default transport
  pools connections.
- `schema_hash` informational TOCTOU: low severity, informational endpoint only.
- Policy dir world-writable: deployment concern, not code concern.
- Rate limiting on batch: valid but not urgent for a sidecar deployment.

---

## Overall Assessment

The Cedar evaluation core is correct and well-implemented. The arc-swap hot-reload
pattern is sound. Fail-closed is properly implemented at every error path. The
rayon-in-spawn_blocking batch pattern is correct.

The performance claims are internally consistent and plausible. The Go/Lua IPC gap
is architecturally explained and documented honestly in RESULTS.md.

The main gaps before production are: (1) the PDP trusts claims without JWT
verification, requiring strict network isolation; (2) the admin endpoint is
unauthenticated; (3) the Go plugin is not viable under concurrent load and should
be formally deprecated; (4) operational observability (audit logs, metrics) is
absent.

The codebase is a solid prototype. The path to production is primarily about
hardening the trust boundary (who can call the PDP with what claims), adding
observability, and picking one plugin implementation (Lua).
