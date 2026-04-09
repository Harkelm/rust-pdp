# Amazon Verified Permissions: Comparison and API Compatibility Analysis

**Date**: 2026-04-09
**Context**: Tech director requested exploration of AWS Amazon Verified Permissions (AVP)
to understand API surface, compatibility path, and performance tradeoffs against the
existing rust-pdp self-hosted Cedar PDP.

---

## Executive Summary

Amazon Verified Permissions is AWS's managed Cedar authorization service (34 API
operations). The rust-pdp prototype already exceeds AVP in raw evaluation performance
(sub-millisecond local vs network-hop latency) and throughput (87K+ RPS vs AVP's 200 RPS
default quota). The key value proposition of matching the AVP API is **portability**: teams
could swap between self-hosted and managed AVP without changing client code, and the API
surface is well-designed for authorization lifecycle management (policy CRUD, templates,
identity sources, schema management).

**Recommendation**: Implement an AVP-compatible API layer on top of the existing Cedar
evaluation engine. This gives teams the managed-service API contract with self-hosted
performance characteristics.

---

## 1. API Surface Comparison

### Authorization Endpoints (Hot Path)

| AVP Operation | rust-pdp Equivalent | Gap |
|---------------|-------------------|-----|
| `IsAuthorized` | `POST /v1/is_authorized` | Request/response format differs (see Section 3) |
| `IsAuthorizedWithToken` | Partial (JWT claims in request body) | No identity source config, no token validation |
| `BatchIsAuthorized` | `POST /v1/batch_is_authorized` | Different batch semantics (see below) |
| `BatchIsAuthorizedWithToken` | Not implemented | Requires identity source + batch |

### Policy Management (Control Plane)

| AVP Operation | rust-pdp Equivalent | Gap |
|---------------|-------------------|-----|
| `CreatePolicy` | File creation + hot-reload | No CRUD API, file-based only |
| `GetPolicy` | `GET /v1/policy-info` (metadata only) | No individual policy retrieval |
| `UpdatePolicy` | File edit + hot-reload | No update API |
| `DeletePolicy` | File deletion + hot-reload | No delete API |
| `ListPolicies` | `GET /v1/policy-info` (count only) | No enumeration |
| `CreatePolicyTemplate` | File-based templates exist | No CRUD API, no runtime linking API |
| `GetPolicyTemplate` / `UpdatePolicyTemplate` / `DeletePolicyTemplate` | Not implemented | -- |
| `ListPolicyTemplates` | Not implemented | -- |
| `BatchGetPolicy` | Not implemented | -- |

### Policy Store Management

| AVP Operation | rust-pdp Equivalent | Gap |
|---------------|-------------------|-----|
| `CreatePolicyStore` / `GetPolicyStore` / etc. | Single store (directory) | No multi-store concept |
| `CreatePolicyStoreAlias` / etc. | Not applicable | Single store |
| `GetSchema` / `PutSchema` | Schema loaded from file | No schema CRUD API |

### Identity Management

| AVP Operation | rust-pdp Equivalent | Gap |
|---------------|-------------------|-----|
| `CreateIdentitySource` / etc. | JWT claims extraction (Tier 1) | No identity source config, no Cognito/OIDC integration |

### Summary

- **Hot path** (IsAuthorized, Batch): Functionally equivalent, format differs
- **Control plane** (policy CRUD, templates, schema): Major gap -- rust-pdp is file-based
- **Identity**: Partial -- JWT claim extraction works but no identity source management

---

## 2. Request/Response Format Comparison

### IsAuthorized Request

**AVP format:**
```json
{
  "policyStoreId": "PSEXAMPLEabcdefg111111",
  "principal": {
    "entityType": "ApiGateway::User",
    "entityId": "alice"
  },
  "action": {
    "actionType": "ApiGateway::Action",
    "actionId": "read"
  },
  "resource": {
    "entityType": "ApiGateway::ApiResource",
    "entityId": "/api/data"
  },
  "context": {
    "contextMap": {
      "ip": { "String": "192.0.2.1" }
    }
  },
  "entities": {
    "entityList": [
      {
        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
        "Attributes": {
          "email": { "String": "alice@example.com" },
          "suspended": { "Boolean": false }
        },
        "Parents": [
          { "EntityType": "ApiGateway::Role", "EntityId": "admin" }
        ]
      }
    ]
  }
}
```

**rust-pdp format:**
```json
{
  "principal": "ApiGateway::User::\"alice\"",
  "action": "ApiGateway::Action::\"read\"",
  "resource": "ApiGateway::ApiResource::\"/api/data\"",
  "context": {},
  "claims": {
    "sub": "alice",
    "email": "alice@example.com",
    "org": "acme",
    "roles": ["admin"],
    "suspended": false
  }
}
```

**Key differences:**

| Element | AVP | rust-pdp |
|---------|-----|----------|
| Principal/Action/Resource | Structured `{ entityType, entityId }` | Cedar UID string `Type::"id"` |
| Context values | Typed wrappers `{ "String": "..." }` | Plain JSON (no type wrappers) |
| Entities | Explicit entity list with typed attributes | Constructed from JWT `claims` object |
| Policy store selector | `policyStoreId` field | N/A (single store) |

### IsAuthorized Response

**AVP format:**
```json
{
  "decision": "ALLOW",
  "determiningPolicies": [
    { "policyId": "SPEXAMPLEabcdefg111111" }
  ],
  "errors": [
    { "errorDescription": "string" }
  ]
}
```

**rust-pdp format:**
```json
{
  "decision": "Allow",
  "diagnostics": {
    "reason": ["policy-id-1"],
    "errors": []
  }
}
```

**Key differences:**

| Element | AVP | rust-pdp |
|---------|-----|----------|
| Decision value | `"ALLOW"` / `"DENY"` (uppercase) | `"Allow"` / `"Deny"` (title case) |
| Policy IDs | `determiningPolicies[].policyId` | `diagnostics.reason[]` (flat strings) |
| Errors | Top-level `errors[]` with `errorDescription` | Nested `diagnostics.errors[]` |

### Batch Differences

| Aspect | AVP | rust-pdp |
|--------|-----|----------|
| Max batch size | 30 | 100 |
| Shared entities | Yes (top-level `entities`) | No (each request independent) |
| Constraint | Principal OR resource must be same across batch | No constraint |
| Token variant | `BatchIsAuthorizedWithToken` | Not implemented |

---

## 3. Performance Comparison

### Latency

| Metric | rust-pdp (local) | AVP (remote) | Ratio |
|--------|------------------|-------------|-------|
| Cedar eval (10 policies) | ~5-10 us | ~5-10 us (same engine) | 1:1 |
| End-to-end single auth | 0.3-0.5 ms | 5-20 ms (network) | 10-60x slower |
| End-to-end batch (30 items) | ~1-2 ms | 5-20 ms (network) | 3-20x slower |

AVP's evaluation engine is the same Cedar Rust crate. The performance difference is
entirely network overhead (TLS handshake, HTTP serialization, AWS API gateway routing).

### Throughput

| Metric | rust-pdp | AVP |
|--------|----------|-----|
| Single-auth RPS (measured) | 87,200 (c=100) | 200 default quota |
| Batch RPS | 111,000 (c=500) | 30 default quota |
| Peak decisions/sec | 192,000 (batch) | 900 (30 RPS x 30 items) |

AVP quotas are adjustable via AWS support, but even with increases, network overhead
caps practical throughput far below local evaluation.

### Cost at Scale

| Monthly Volume | AVP Cost | Self-Hosted Cost (estimate) |
|---------------|----------|---------------------------|
| 1M requests | $5 | ~$5-10 (compute) |
| 10M requests | $50 | ~$5-10 (same instance) |
| 100M requests | $500 | ~$20-50 (2-3 instances) |
| 1B requests | $5,000 | ~$100-200 (cluster) |

Self-hosted cost advantage grows with scale. At 1B requests/month, self-hosted is
25-50x cheaper.

---

## 4. Feature Comparison

### What AVP Provides That rust-pdp Does Not

| Feature | AVP | rust-pdp | Priority |
|---------|-----|----------|----------|
| Policy CRUD API | Full REST API | File-based | HIGH -- needed for API compat |
| Policy templates (runtime linking) | Full API | Template exists, no linking API | HIGH |
| Identity source management | Cognito + OIDC | JWT claim extraction only | MEDIUM |
| Token-based auth (IsAuthorizedWithToken) | JWT validation + entity mapping | Claims passed explicitly | MEDIUM |
| Schema management API | GetSchema / PutSchema | File-based | MEDIUM |
| Multi-store (policyStoreId) | Yes | Single store | LOW for MVP |
| Automated reasoning (policy analysis) | Yes | Not available | LOW |
| CloudTrail audit logging | Built-in | Not implemented | MEDIUM (Phase 1) |
| Policy store aliases | Named aliases | N/A | LOW |
| Resource tagging | AWS resource tags | N/A | LOW |
| KMS encryption | Optional | N/A | LOW |

### What rust-pdp Provides That AVP Does Not

| Feature | rust-pdp | AVP |
|---------|----------|-----|
| Sub-millisecond local evaluation | Yes | No (network hop) |
| 87K+ RPS single-instance | Yes | 200 RPS default quota |
| Policy hot-reload (file watcher) | Yes | N/A (managed store) |
| Kong-native Lua plugin | Yes | No (HTTP generic) |
| Batch >30 items | Yes (100 max) | No (30 max) |
| Unconstrained batch (mixed principals) | Yes | No (same principal OR resource required) |
| No vendor lock-in | Yes | AWS-only |
| Decision cache (Kong plugin) | Per-worker TTL cache | Client-side only |
| Fail-closed enforcement | Explicit (503 vs 403) | Client-side responsibility |

---

## 5. API Compatibility Implementation Path

### Phase A: AVP-Compatible Authorization Endpoints

Add new endpoints that accept/return AVP-format JSON while using the same Cedar engine:

```
POST /avp/is-authorized          -> maps to IsAuthorized
POST /avp/is-authorized-with-token -> maps to IsAuthorizedWithToken
POST /avp/batch-is-authorized    -> maps to BatchIsAuthorized
```

**Request translation layer:**
1. Parse AVP-format `EntityIdentifier` -> Cedar `EntityUid`
2. Parse typed context values (`{ "String": "..." }`) -> Cedar `RestrictedExpression`
3. Parse AVP entity list -> Cedar `Entities`
4. Ignore `policyStoreId` (single store) or use as directory selector (multi-store)
5. Return AVP-format response (uppercase decision, `determiningPolicies` array)

**Estimated effort**: 2-3 days for the translation layer + tests.

### Phase B: Policy Management API

Add CRUD endpoints matching AVP's policy management surface:

```
POST   /avp/policy-stores/{storeId}/policies     -> CreatePolicy
GET    /avp/policy-stores/{storeId}/policies/{id} -> GetPolicy
PUT    /avp/policy-stores/{storeId}/policies/{id} -> UpdatePolicy
DELETE /avp/policy-stores/{storeId}/policies/{id} -> DeletePolicy
GET    /avp/policy-stores/{storeId}/policies      -> ListPolicies
```

**Requires**: Policy storage backend (file-based or SQLite) with ID generation,
TOML/JSON metadata sidecars, atomic policy updates with validation.

**Estimated effort**: 5-8 days.

### Phase C: Template Linking API

```
POST /avp/policy-stores/{storeId}/policies  (with templateLinked definition)
```

Wire up Cedar's `PolicySet::link()` at runtime. Store template-linked policy bindings
in a config file or DB alongside the template .cedar files.

**Estimated effort**: 2-3 days.

### Phase D: Identity Source + Token-Based Auth

```
POST /avp/is-authorized-with-token
```

Add JWT validation (signature verification, expiration check) and token-to-entity
mapping (similar to AVP's Cognito/OIDC identity source configuration). Map `sub` claim
to principal, `groups`/`roles` to parent entities, other claims to attributes or context.

**Estimated effort**: 3-5 days (JWT validation library needed -- `jsonwebtoken` crate).

---

## 6. Measured Benchmark Results

### AVP Format Overhead (Criterion, 100 samples, 95% CI)

Benchmarks run on i7-14700KF (20c/28t), 32GB RAM, Rust 1.92, Cedar 4.9.1.
Source: `pdp/benches/avp_format_overhead.rs`.

#### Parse-Only (No Cedar Evaluation)

| Format | Mean | Notes |
|--------|------|-------|
| Native (claims-based) | 9.44 us | Cedar UID string parsing + entity construction from claims |
| AVP (typed wrappers) | 14.04 us | Structured identifiers + typed value wrappers + entity list |
| **Overhead** | **+4.6 us (+49%)** | Typed value wrapper deserialization dominates |

#### Full Path (Parse + Cedar Evaluation)

| Format | Mean | Notes |
|--------|------|-------|
| Native full path | 20.22 us | Parse + evaluate against 6 production policies |
| AVP full path | 25.24 us | Parse + evaluate (same Cedar engine) |
| **Overhead** | **+5.0 us (+25%)** | Fixed overhead, amortized over evaluation |

**Insight**: The ~5us overhead is constant regardless of policy count. At realistic
workloads (10-100 policies, 10-25us eval), AVP format adds 20-50% parse overhead.
At larger policy sets (1000+, 450us eval), the overhead becomes negligible (<2%).

#### Response Serialization

| Format | Mean | Notes |
|--------|------|-------|
| Native response | 50.1 ns | `{ decision, diagnostics: { reason, errors } }` |
| AVP response | 52.1 ns | `{ decision, determiningPolicies, errors }` |
| **Overhead** | **+2 ns (+4%)** | Negligible |

#### Batch Throughput

| Batch Size | AVP Format | Native Format | Overhead |
|------------|-----------|---------------|----------|
| 10 items | 249.1 us | 203.7 us | +22% |
| 30 items (AVP max) | 747.6 us | 611.9 us | +22% |
| 100 items (native max) | N/A | 2.03 ms | -- |

**Key finding**: AVP's 30-item batch limit means 3.3x fewer decisions per batch call
compared to native's 100-item limit. At 30 items, native completes in 612us; getting
100 items through AVP requires 4 batch calls (2.99ms total) vs native's single 2.03ms call.

### Cedar Evaluation Baselines (Existing Benchmarks)

#### Realistic Production Scenarios (6 policies + schema)

| Scenario | Mean | Decision |
|----------|------|----------|
| admin_read | 9.6 us | Allow |
| viewer_delete_deny | ~9 us | Deny |
| suspended_admin_deny | ~9 us | Deny (forbid) |
| data_scope_allow | ~9 us | Allow |
| cross_org_deny | ~9 us | Deny |
| multi_role_write | 9.14 us | Allow |

#### Policy Scaling (Noise Policies Added)

| Production + Noise | Mean | Per-Policy Cost |
|-------------------|------|-----------------|
| 6 (production only) | 9.6 us | 1.6 us/policy |
| 6 + 100 noise | 54.4 us | ~0.5 us/policy |
| 6 + 500 noise | 231.8 us | ~0.5 us/policy |
| 6 + 1000 noise | 453.8 us | ~0.5 us/policy |

### What Requires AWS Account to Benchmark

| Benchmark | Why |
|-----------|-----|
| AVP round-trip latency from our region | Network measurement (estimated 5-20ms) |
| AVP batch shared-entity optimization | Verify AWS's shared entity dedup claims |
| AVP quota behavior at limit | Rate limit characteristics (429 response shape, retry headers) |
| AVP automated reasoning speed | No local equivalent (SMT-based analysis) |

### Cost Projection

| Monthly Volume | AVP Cost | Self-Hosted (3x c5.large HA) | Ratio |
|---------------|----------|------------------------------|-------|
| 1M | $5 | ~$75 (compute) | AVP cheaper |
| 10M | $50 | ~$75 | Breakeven |
| 100M | $500 | ~$75 | 6.7x self-hosted advantage |
| 1B | $5,000 | ~$150 (scale up) | 33x self-hosted advantage |

Self-hosted cost advantage starts at ~10M requests/month and grows linearly.

---

## 7. Key Risks and Considerations

### Risk: AVP API Stability
AVP upgraded from Cedar 2 to Cedar 4 with breaking changes. The API surface itself
(request/response format) has been stable, but Cedar language semantics changes could
create subtle behavioral differences between our local Cedar 4.9.1 and AVP's Cedar
version.

**Mitigation**: Track AVP's Cedar version. Currently Cedar 4 (upgraded August 2025).
Pin our cedar-policy dependency to match AVP's known version when API compat is active.

### Risk: Entity Format Divergence
AVP recently (February 2025) started accepting native Cedar JSON entity format alongside
their custom typed-wrapper format. This reduces the translation burden but creates two
valid input formats to support.

**Mitigation**: Accept both formats. Detect format from presence of `EntityType` (AVP)
vs `type` (Cedar native) keys.

### Risk: Batch Semantics Mismatch
AVP requires either principal or resource to be identical across all batch requests.
Our current batch has no such constraint. Matching the AVP API means adding this
validation, which would be a regression for callers using unconstrained batches.

**Mitigation**: Keep native `/v1/batch_is_authorized` unconstrained. Apply the
constraint only on the AVP-compat endpoint `/avp/batch-is-authorized`.

### Risk: Single Identity Source Limit
AVP allows only 1 identity source per policy store. If we model this, it limits
flexibility compared to supporting multiple JWT issuers.

**Mitigation**: Implement identity source config but allow multiple sources on
self-hosted (superset of AVP behavior).

---

## 8. Recommendation

### Immediate (Can Do Now)

1. **Create AVP-format benchmark suite** -- Measure the overhead of parsing/translating
   AVP-format requests vs native format. This quantifies the cost of API compatibility.

2. **Implement AVP authorization endpoint** (Phase A) -- The translation layer is
   straightforward and gives immediate API compatibility for the hot path.

3. **Document AVP entity format mapping** -- Map our existing schema and entity types to
   AVP's format with concrete examples.

### Requires AWS Account

4. **Round-trip latency measurement** -- Deploy a minimal Lambda or test harness to
   measure actual AVP authorization latency from your region/VPC.

5. **Quota stress testing** -- Hit AVP's 200 RPS default and measure behavior at/above
   quota (throttling characteristics, error responses).

### Requires Design Decision

6. **Multi-store support** -- Does the deployment need multiple policy stores (multi-tenant
   policy isolation) or is single-store sufficient? This affects the scope of Phase B.

7. **Identity source scope** -- Full Cognito/OIDC token validation or continue with
   pre-validated JWT claims from Kong's auth plugin?

---

## 9. Conclusion

The rust-pdp already implements the core authorization engine that AVP wraps. Adding
AVP API compatibility is a translation layer exercise, not an engine rewrite. The
performance advantage of local evaluation (10-60x lower latency, 400x+ higher throughput)
makes self-hosted the clear winner for API gateway use cases where the PDP is colocated.

The AVP API surface is well-designed and worth matching for portability -- teams get a
standardized authorization API that could swap between self-hosted and managed depending
on their operational preferences.

**Critical blocker for full benchmarking**: AWS account access to measure actual AVP
latency and quota behavior. Everything else can be benchmarked locally.
