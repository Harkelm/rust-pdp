# GPT Cross-Review: Cedar PDP Prototype

**Source**: GPT (via Codex CLI, model gpt-5.4)
**Date**: 2026-04-08
**Scope**: Security, correctness, Cedar API usage, arc-swap soundness, Go plugin failure handling
**Files reviewed**: handlers.rs, policy.rs, entities.rs, kong-plugin-go/main.go
**Tokens used**: 16,065

---

## Findings (Ranked by Severity)

### High: Go plugin bypasses the validated entity path entirely

The Kong plugin sends only `principal`/`action`/`resource` strings (main.go lines
100-103), which drives the Rust handler into the legacy branch that uses
`Entities::empty()` (handlers.rs lines 76, 81). Any Cedar policy relying on roles,
org membership, `suspended`, scopes, or resource attributes will either never match
or evaluate with missing data.

This is both a correctness gap and a security gap: the documented `validate_entities`
mitigation (P0-2) is not active on the actual Kong enforcement path.

### High: X-Consumer-ID header fallback is a likely principal-spoofing vector

The Go plugin trusts `X-Consumer-ID` as a fallback identity source (main.go lines
49-51). If Kong does not strip this header from untrusted client input before the
plugin executes, a client can inject an arbitrary principal ID. Header fallback should
be treated as untrusted unless it originates from trusted Kong internal state.

### High: Entity type name and action model mismatch between plugin and PDP

The Go plugin emits `User`, `Action`, and `Resource` UIDs with raw lowercased HTTP
methods (e.g., `"get"`) (main.go lines 56, 60, 64). The Rust entity builder uses
`ApiGateway::User`, `ApiGateway::Action`, `ApiGateway::ApiResource` and maps methods
to `"read"`, `"write"`, `"delete"` (entities.rs lines 35, 48, 112-114). These are
two separate policy dialects. Unless both are maintained intentionally, one path is
wrong -- this will cause systematic deny or silently bypass intended policy structure.

### High: PDP non-200 responses misclassified as authorization denies

The plugin special-cases transport failure and HTTP 503, but a 400/500/502 from the
PDP is decoded into `pdpResponse`; because `ErrorResponse` has no `decision` field,
`Decision` stays empty and falls through to 403 (main.go lines 159, 177, 182). This
turns PDP bugs, contract drift, and internal server errors into "forbidden" rather
than "service unavailable". The 503-vs-403 split is not clean.

### Medium: Unknown HTTP methods silently mapped to "read"

The action mapper in entities.rs (line 44) maps all unrecognised methods to `"read"`.
Methods like `TRACE`, `CONNECT`, or custom verbs would be authorized under read
semantics. For an authorization system, unknown methods should be rejected or mapped
to a distinct action that defaults to deny.

### Medium: Resource attributes fabricated from caller-supplied claims

`owner_org` on the `ApiResource` entity is set from `claims.org` (entities.rs line
101); `classification` is hard-coded to `"internal"` (entities.rs line 100);
`department` is empty (entities.rs line 99). If policies use these attributes,
authorization decisions are being made on attacker-controlled or placeholder data.
This is a trust-boundary problem, not merely a missing feature.

### Medium: Cedar request schema validation disabled at request construction

`Request::new(..., None)` (handlers.rs lines 90-96) skips principal/action/resource
validation against the loaded schema. In the claims path this is mostly contained
since types are constructed programmatically, but in the legacy path arbitrary entity
types are accepted without schema checking. The schema is already loaded; passing it
here is a one-line fix.

### Low: Hot-reload metadata not atomically consistent with policy/schema tuple

The auth state swap is atomic (policy.rs line 47), but `schema_hash` and
`last_reload_epoch_ms` are updated separately (policy.rs lines 48-49). The
`policy_info` endpoint can briefly report mixed metadata from different generations.
This does not affect authorization decisions, but the info endpoint is not a true
snapshot.

### Low: Policy/schema file load order is non-deterministic

`read_dir()` does not guarantee sorted order (policy.rs line 66). Schema hash
stability, reload reproducibility, and diagnostic output are weaker than they need
to be. Sorting entries before processing is a low-cost improvement.

---

## Answers to Specific Questions

### 1. Security concerns the team may have missed

The main missed issue is that the real Kong enforcement path is currently the
unsafe/legacy one, not the validated entity path. This makes the documented
`validate_entities` mitigation (P0-2) largely irrelevant for production traffic.

The `X-Consumer-ID` fallback is a likely spoofing bug unless the header is provably
stripped before the plugin runs.

The fabricated resource attributes in entities.rs (lines 97-101) are a subtle
trust-boundary problem: policies that reference `classification`, `owner_org`, or
`department` on resources are making decisions on caller-supplied or hard-coded data.

### 2. Cedar API usage correctness for cedar-policy v4

Mostly correct:

- `Authorizer::new()` + `is_authorized(&request, &policy_set, &entities)` is the
  standard v4 pattern (handlers.rs lines 100-101).
- `Validator::new(schema.clone()).validate(...)` is the correct validation flow
  (policy.rs lines 91-92).
- `Entities::from_entities(..., schema)` is appropriate for schema-checked entity
  construction (entities.rs line 105).

The one gap: `Request::new` is called with `None` for the schema (handlers.rs line
95). The current usage is valid but more permissive than production warrants. Pass
the loaded schema to enable request-level type checking.

### 3. Arc-swap pattern for hot-reload: soundness and races

Sound for authorization decisions. The handler does one `store.load()` and holds the
guard for the duration of the request (handlers.rs lines 59-60). The tuple
`(PolicySet, Schema)` is swapped as a single `Arc` (policy.rs line 47), so no
request can observe a mixed policy/schema pair.

The only observable race is on metadata: `state`, `schema_hash`, and
`last_reload_epoch_ms` are not a single atomic snapshot. This affects observability
endpoints, not authorization correctness.

### 4. Go plugin 503 vs 403 distinction

Not fully correct. The intended invariant is:

- Definitive PDP authorization result: `Allow` passes through, `Deny` returns 403.
- PDP unavailable, broken, or mismatched: 503 + Retry-After.

The current code handles transport errors and literal upstream 503. Every other
PDP-side failure (400, 500, 502, decode error on unexpected body) falls through to
403. The fix is to require `resp.StatusCode == 200` before decoding `Decision`, and
treat any other status as enforcement failure (503).

### 5. Changes required before production

1. Remove the legacy string-UID path for Kong traffic. Have the plugin send
   structured claims/request context so the PDP builds schema-validated entities on
   every request.
2. Remove `X-Consumer-ID` header fallback, or prove the header is sourced from
   trusted Kong internal state only.
3. Unify the Cedar namespace and action model across plugin and PDP. `User/Action/
   Resource + get/post` and `ApiGateway::* + read/write/delete` are two separate
   systems; one must be eliminated.
4. Treat all non-200 PDP responses as enforcement failure (503), not deny (403).
5. Pass `Some(schema)` to `Request::new`. Reject unknown HTTP methods instead of
   silently mapping them to `"read"`.
6. Do not derive resource attributes from user claims. Resolve them from an
   authoritative source or remove policies that depend on them.
7. Sort policy/schema files on load. Make reload metadata atomic with the policy
   tuple if snapshot-consistent observability is needed.
8. Add an authenticated Kong-to-PDP channel before leaving prototype stage.
   Loopback-only or Unix socket is preferable to unauthenticated HTTP if services
   are co-located.

**Residual risk after the above**: claims provenance and resource metadata provenance
require an explicit trust contract. That is the part most likely to produce subtle
authorization bugs during migration.
