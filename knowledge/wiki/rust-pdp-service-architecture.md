# Rust PDP Service Architecture

Compiled from `knowledge/raw/2026-04-08-rust-pdp-patterns.md` on 2026-04-08.

## Overview

Design patterns for building a Rust-based Cedar Policy Decision Point (PDP) as an
HTTP/gRPC microservice. Covers framework selection, policy hot-reload, entity resolution,
caching, observability, and the existing open-source reference implementations.

## Recommended Stack

```toml
[dependencies]
cedar-policy = "4.9"
axum = "0.8"           # HTTP framework
tonic = "0.12"         # gRPC framework
tokio = { version = "1", features = ["full"] }
arc-swap = "1.7"       # Lock-free policy hot-swap
notify = "7"           # File system watcher
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
moka = { version = "0.12", features = ["sync"] }  # Decision cache
```

### Framework Choice: axum + tonic

- **axum**: Built on hyper/tower, async-native, minimal overhead. Extractors for
  request parsing, `State` for shared app state, tower middleware for cross-cutting.
- **tonic**: Rust gRPC on tokio/prost/hyper. Proto-defined services, interceptors,
  native streaming, TLS.
- **Combined**: `axum_tonic` crate serves both REST and gRPC on the same port.
  Health/metrics/admin over HTTP, authz decisions over gRPC.

## API Design

### Primary Endpoint: Cedar-native

`POST /v1/is_authorized`

```json
// Request
{
    "principal": "User::\"alice\"",
    "action": "Action::\"view\"",
    "resource": "Document::\"doc-123\"",
    "context": {"ip_addr": "10.0.1.1", "mfa": true},
    "entities": [...]
}

// Response
{
    "decision": "Allow",
    "diagnostics": {
        "reason": ["policy0"],
        "errors": []
    }
}
```

### AuthZen Standard Endpoint (Interop)

`POST /access/v1/evaluation`

```json
// Request (4-tuple model)
{
    "subject": { "type": "user", "id": "alice@example.com", "properties": {...} },
    "resource": { "type": "account", "id": "123", "properties": {...} },
    "action": { "name": "can_read", "properties": {"method": "GET"} },
    "context": { "time": "2026-04-08T14:30:00Z" }
}

// Response
{
    "decision": true,
    "context": { "id": "eval-001", "reason_admin": {"en": "Matched policy P-1234"} }
}
```

**Recommendation**: Implement AuthZen on external API for interoperability, map to
Cedar types internally. This allows engine-swapping without PEP changes.

### Batch Endpoint

`POST /access/v1/evaluations` -- evaluate multiple resources in one call.
Semantics: `execute_all` (default), `deny_on_first_deny`, `permit_on_first_permit`.

## Policy Hot-Reload

### Pattern: arc-swap + file watcher

```rust
pub struct PolicyStore {
    policy_set: ArcSwap<PolicySet>,
    schema: ArcSwap<Schema>,
    path: String,
}

impl PolicyStore {
    // Lock-free read -- called on every authz request
    pub fn get_policies(&self) -> arc_swap::Guard<Arc<PolicySet>> {
        self.policy_set.load()
    }

    // Atomic swap -- called on reload
    pub fn reload(&self) -> Result<(), Error> {
        let (new_policies, new_schema) = Self::load_from_dir(&self.path)?;
        new_policies.validate(&new_schema)?;  // validate BEFORE swap
        self.policy_set.store(Arc::new(new_policies));
        self.schema.store(Arc::new(new_schema));
        Ok(())
    }
}
```

### Why arc-swap over RwLock

- All reads are lock-free and mostly wait-free (critical for PDP: 99.99%+ reads)
- No contention between concurrent reads
- Writes are atomic -- readers never see partial updates
- `Cache` wrapper provides 10-25x speedup for hot-path reads

### Reload Triggers

1. **File watcher** (`notify` crate): Watch policy directory, reload on change
2. **SIGHUP handler**: Manual reload via signal
3. **HTTP admin endpoint**: `POST /admin/reload`
4. **Periodic polling**: Timer-based check (cedar-local-agent uses 15s minimum)

**Critical**: Validation-before-swap ensures broken policy files never become active.

## Policy Store Patterns

| Pattern | Description | Best For |
|---------|-------------|----------|
| **File-based** | .cedar/.cedarschema in directory, git-versioned | Starting point, simplest |
| **Database-backed** | Rows with policy text, LISTEN/NOTIFY for changes | Multi-instance coordination |
| **S3/Object storage** | Bundled tarballs, etag-based change detection | CI/CD pipeline deployment |
| **Git + file watcher** | Git repo as source of truth, webhook triggers pull | Audit trail + rollback |

## Entity Resolution

Cedar requires entities (principal, resource, relationships) with each request.
Cedar is deliberately stateless -- the caller must supply all relevant entity data.

### Recommended Pattern

1. **Static entities** (roles, groups, org hierarchy): Load on startup, cache in
   `ArcSwap<Entities>`, refresh on change
2. **Principal attributes**: Accept from PEP in the request (from JWT or session store)
3. **Resource attributes**: Resolve via database with connection pooling, cache with TTL
4. **Context**: Accept from PEP (IP, time, MFA status)

**Security**: PDP should NOT trust entity data from PEP for security-critical attributes.
PEP provides hints (principal ID, resource ID), PDP resolves authoritative data from
its own sources.

## Decision Caching

```rust
use moka::sync::Cache;

struct DecisionCache {
    cache: Cache<String, Decision>,  // 10,000 entries, 60s TTL
}

fn cache_key(principal: &str, action: &str, resource: &str) -> String {
    format!("{}:{}:{}", principal, action, resource)
}
```

Invalidation strategies:
- TTL-based (simplest, 30-60s acceptable for most APIs)
- Policy-change-triggered (invalidate all on reload)
- Entity-change-triggered (invalidate affected entries)
- Never cache `forbid` decisions (may be temporary)

## Observability

### Health Endpoints

- `GET /health/live` -- process alive (always 200)
- `GET /health/ready` -- policies loaded, entity store accessible
- `GET /health/startup` -- initial load complete

### Metrics (Prometheus)

```
pdp_decisions_total{decision="allow|deny"}
pdp_evaluation_duration_seconds_bucket{le="0.001|0.01|..."}
pdp_policies_loaded_total
pdp_policy_reload_total{status="success|failure"}
pdp_entity_cache_hit_total / pdp_entity_cache_miss_total
pdp_evaluation_errors_total{type="policy_error|entity_error"}
```

### Structured Logging (tracing)

```rust
#[instrument(skip(policies, entities), fields(
    principal = %request.principal(),
    action = %request.action(),
    resource = %request.resource(),
))]
fn evaluate(request: &Request, policies: &PolicySet, entities: &Entities) -> Response {
    // Decision audit: principal, action, resource, decision, determining policies, timestamp
}
```

### Error Handling: Default-Deny on Errors

```rust
match evaluate_authorization(request).await {
    Ok(response) => response,
    Err(_) => AuthzResponse { decision: false, error: Some("internal error".into()) }
}
```

Fail-closed by default. Never fail-open unless explicitly configured.

## Architecture Diagram

```
                +-------------------+
                |   Kong Gateway    |
                | (Go/Lua plugin)   |
                +--------+----------+
                         | HTTP/gRPC
                         v
                +-------------------+
                |   Rust PDP        |
                |   (axum + tonic)  |
                |                   |
                | /v1/is_authorized | <-- Cedar-native
                | /access/v1/eval   | <-- AuthZen
                | /admin/reload     | <-- Admin
                | /health/*         | <-- Health
                | /metrics          | <-- Prometheus
                +--------+----------+
                         |
          +--------------+--------------+
          |              |              |
 +--------v---+  +------v------+  +----v-------+
 | PolicyStore |  | EntityCache |  | EntityDB   |
 | (arc-swap)  |  | (arc-swap)  |  | (deadpool) |
 | .cedar files|  | roles/groups|  | per-request|
 +-------------+  +-------------+  +------------+
```

## Reference Implementations

| Project | Type | Strengths | Limitations |
|---------|------|-----------|-------------|
| **cedar-agent** (Permit.io) | HTTP server | Simple API, Swagger docs | In-memory only, no gRPC, no hot-reload |
| **cedar-local-agent** (AWS) | Rust library | File providers, hot-reload, OCSF audit | Library only, file-based only |
| **OPAL + cedar-agent** | Distribution layer | Policy lifecycle mgmt, push updates | Additional infrastructure |

## Batch Evaluation

For batch authorization, evaluate concurrently with `spawn_blocking` (Cedar eval is
CPU-bound):

```rust
use tokio::task::JoinSet;

async fn batch_evaluate(requests: Vec<AuthzRequest>) -> Vec<Decision> {
    let mut set = JoinSet::new();
    for req in requests {
        set.spawn_blocking(move || authorizer.is_authorized(&req, &policies, &entities));
    }
    // collect results
}
```

## Sources

- cedar-policy crate: docs.rs/cedar-policy
- cedar-agent: github.com/permitio/cedar-agent
- cedar-local-agent: github.com/cedar-policy/cedar-local-agent
- AuthZen specification: openid.net/specs/authorization-api-1_0.html
- arc-swap: docs.rs/arc-swap
- axum_tonic: docs.rs/axum_tonic
