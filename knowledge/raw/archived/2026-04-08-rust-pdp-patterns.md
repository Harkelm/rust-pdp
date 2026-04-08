---
source: web-research
date: 2026-04-08
project: rust-pdp
tags: [rust, pdp, service-architecture, cedar, grpc]
---

# Rust-Based Cedar Policy Decision Point (PDP) -- Research Findings

## 1. Rust Web Frameworks for Low-Latency Authz Services

Three primary options, each with distinct tradeoffs:

### axum (recommended for HTTP/JSON PDP)

- Built on `hyper` and `tower`, async-native with tokio runtime
- Extractors for request parsing, `State` for shared application state
- Minimal overhead, strong ecosystem (tower middleware for timeouts, tracing, compression)
- Clean integration with tonic for dual HTTP+gRPC on the same port via `axum_tonic` crate
- Onion architecture maps cleanly: presentation (routes) / application (services) / domain (authz logic) / infrastructure (policy stores)

### tonic (recommended for gRPC PDP)

- Rust gRPC framework built on `tokio`, `prost` (protobuf), and `hyper`
- Define service with `.proto` files, `tonic-build` generates Rust traits
- Native streaming, interceptors (for auth, logging), TLS support
- Key dependencies: `tonic = "0.12"`, `prost = "0.13"`, `tokio` with `rt-multi-thread`
- Interceptors provide natural hook points for request logging and metrics

### axum + tonic combined (recommended for production)

- The `axum_tonic` crate enables serving both REST and gRPC on the same port
- Pattern: `RestGrpcService::new(rest_router, grpc_router).into_make_service()`
- Allows health checks, metrics, and admin APIs over HTTP while authz decisions flow over gRPC
- `tonic_web` enables browser-based gRPC-Web clients alongside native gRPC

### actix-web

- Higher throughput in some benchmarks but less composable middleware
- Harder to integrate with tonic for hybrid gRPC/REST
- Less community momentum than axum for new projects

**Recommendation:** axum + tonic for hybrid REST/gRPC, with tower middleware for cross-cutting concerns.


## 2. Embedding the cedar-policy Crate

### Crate: `cedar-policy` (current version: 4.4.1)

Core API surface:

```rust
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName,
    EntityUid, PolicySet, Request, Response, Schema,
};
```

### Creating an Authorizer

```rust
let authorizer = Authorizer::new();
```

The `Authorizer` is stateless, cheap to create, and `Clone`. It does not hold policies or entities -- those are passed per-request.

### Loading Policies

From a string (Cedar policy syntax):
```rust
let policy_src = r#"
permit(
    principal == User::"alice",
    action == Action::"view",
    resource == File::"93"
);
"#;
let policy_set: PolicySet = policy_src.parse().unwrap();
```

From a file at runtime:
```rust
let policy_src = std::fs::read_to_string("./policies.cedar").unwrap();
let policy_set: PolicySet = policy_src.parse().unwrap();
```

Multiple policies parse together -- Cedar concatenates them in one `PolicySet`.

### Creating Entities

From JSON string:
```rust
let entities_json = r#"[
    {
        "uid": {"type": "User", "id": "alice"},
        "attrs": {"age": 19, "department": "engineering"},
        "parents": [{"type": "Group", "id": "admins"}]
    }
]"#;
let entities = Entities::from_json_str(entities_json, None).unwrap();
```

With schema validation:
```rust
let entities = Entities::from_json_str(entities_json, Some(&schema)).unwrap();
```

From domain types via `Entity::new()`:
```rust
use cedar_policy::{Entity, RestrictedExpression};
use std::collections::{HashMap, HashSet};

let uid = EntityUid::from_type_name_and_id(
    EntityTypeName::from_str("User").unwrap(),
    EntityId::from_str("alice").unwrap(),
);
let mut attrs = HashMap::new();
attrs.insert(
    "department".to_owned(),
    RestrictedExpression::new_string("engineering".to_owned()),
);
let parents = HashSet::new();
let entity = Entity::new(uid, attrs, parents).unwrap();
```

### Building Requests

```rust
let principal = r#"User::"alice""#.parse().unwrap();
let action = r#"Action::"view""#.parse().unwrap();
let resource = r#"File::"93""#.parse().unwrap();
let context = Context::empty();

let request = Request::new(
    principal,   // Option<EntityUid> -- Some for known, None for unknown
    action,      // Option<EntityUid>
    resource,    // Option<EntityUid>
    context,     // Context
    None,        // Option<&Schema> -- validates request shape if provided
).unwrap();
```

Context from JSON:
```rust
let ctx_file = std::fs::File::open("./context.json").unwrap();
let context = Context::from_json_file(ctx_file, None).unwrap();
```

### Evaluating Requests

```rust
let response: Response = authorizer.is_authorized(&request, &policy_set, &entities);

match response.decision() {
    Decision::Allow => println!("ALLOW"),
    Decision::Deny => println!("DENY"),
}

// Diagnostics: which policies contributed to the decision
for reason in response.diagnostics().reason() {
    println!("Determined by policy: {}", reason);
}
for error in response.diagnostics().errors() {
    println!("Policy error: {}", error);
}
```

### Partial Evaluation (feature: `partial-eval`)

For cases where not all request components are known at evaluation time:

```rust
let request = RequestBuilder::default()
    .principal(Some(r#"User::"alice""#.parse().unwrap()))
    .action(Some(r#"Action::"view""#.parse().unwrap()))
    // resource left unknown
    .context(context)
    .build()
    .unwrap();

match authorizer.is_authorized_partial(&request, &policies, &entities) {
    PartialResponse::Concrete(r) => println!("Decision: {:?}", r),
    PartialResponse::Residual(r) => {
        for policy in r.residuals().policies() {
            println!("Residual policy: {policy}");
        }
    }
}
```


## 3. PDP Request/Response Model

### AuthZen Standard (OpenID Foundation -- Authorization API 1.0)

The industry-standard PDP API model. Endpoint: `POST /access/v1/evaluation`

**Request (4-tuple model):**
```json
{
    "subject": {
        "type": "user",
        "id": "alice@acmecorp.com",
        "properties": {
            "department": "Sales",
            "ip_address": "172.217.22.14"
        }
    },
    "resource": {
        "type": "account",
        "id": "123",
        "properties": {
            "owner": "bob@acmecorp.com"
        }
    },
    "action": {
        "name": "can_read",
        "properties": {
            "method": "GET"
        }
    },
    "context": {
        "time": "2026-04-08T14:30:00Z"
    }
}
```

- `subject.type` + `subject.id` = REQUIRED. Maps to Cedar `principal`.
- `resource.type` + `resource.id` = REQUIRED. Maps to Cedar `resource`.
- `action.name` = REQUIRED. Maps to Cedar `action`.
- `*.properties` = OPTIONAL. Additional attributes for ABAC evaluation.
- `context` = OPTIONAL. Transient/session data (time, IP, MFA status).

**Response:**
```json
{
    "decision": true,
    "context": {
        "id": "eval-001",
        "reason_admin": {"en": "Matched policy P-1234"},
        "reason_user": {"en": "Access granted"}
    }
}
```

- `decision` = boolean (`true` = allow, `false` = deny). Simpler than XACML's 4-value model.
- `context` = OPTIONAL. Diagnostic info, human-readable reasons, policy IDs.

**Batch endpoint:** `POST /access/v1/evaluations`
```json
{
    "subject": {"type": "user", "id": "alice"},
    "action": {"name": "can_read"},
    "evaluations": [
        {"resource": {"type": "doc", "id": "doc1"}},
        {"resource": {"type": "doc", "id": "doc2"}}
    ],
    "options": {
        "evaluations_semantic": "execute_all"
    }
}
```

Semantics: `execute_all` (default), `deny_on_first_deny`, `permit_on_first_permit`.

### Cedar-native model (cedar-agent style)

Endpoint: `POST /v1/is_authorized`

**Request:**
```json
{
    "principal": "User::\"alice\"",
    "action": "Action::\"view\"",
    "resource": "Document::\"doc-123\"",
    "context": {"ip_addr": "10.0.1.1", "mfa": true},
    "entities": [...]
}
```

**Response:**
```json
{
    "decision": "Allow",
    "diagnostics": {
        "reason": ["policy0"],
        "errors": []
    }
}
```

**Recommendation:** Implement AuthZen on the external API surface for interoperability. Map to Cedar types internally. This allows swapping Cedar for OPA or other engines later without changing the PEP integration.


## 4. Policy Hot-Reload Without Restart

### Pattern: `arc-swap` + file watcher

The recommended Rust pattern for hot-reloading policies without restarting the PDP:

**Core structure:**
```rust
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct PolicyStore {
    policy_set: ArcSwap<PolicySet>,
    schema: ArcSwap<Schema>,
    path: String,
}

impl PolicyStore {
    pub fn new(path: &str) -> Result<Self, Error> {
        let (policy_set, schema) = Self::load_from_dir(path)?;
        Ok(Self {
            policy_set: ArcSwap::from_pointee(policy_set),
            schema: ArcSwap::from_pointee(schema),
            path: path.to_string(),
        })
    }

    /// Lock-free read -- called on every authz request
    pub fn get_policies(&self) -> arc_swap::Guard<Arc<PolicySet>> {
        self.policy_set.load()
    }

    /// Atomic swap -- called on reload
    pub fn reload(&self) -> Result<(), Error> {
        let (new_policies, new_schema) = Self::load_from_dir(&self.path)?;
        // Validate before swapping
        new_policies.validate(&new_schema)?;
        self.policy_set.store(Arc::new(new_policies));
        self.schema.store(Arc::new(new_schema));
        Ok(())
    }
}
```

**Why `arc-swap` over `RwLock`:**
- All reads are lock-free and mostly wait-free
- No contention between concurrent reads (critical for PDP where reads dominate 99.99%+)
- `RwLock` degrades under concurrent read load; `arc-swap` maintains performance
- Writes are atomic -- readers never see partial updates
- The `Cache` wrapper provides 10-25x speedup for hot-path reads

**Reload triggers (choose one or combine):**

1. **File watcher** (`notify` crate): Watches policy directory, triggers reload on change
2. **SIGHUP handler**: `kill -HUP <pid>` triggers manual reload
3. **HTTP admin endpoint**: `POST /admin/reload` for API-driven reload
4. **Periodic polling**: Timer-based check (cedar-local-agent uses 15-second minimum)

**Validation-before-swap** is critical: parse and validate new policies against schema before atomically swapping. If validation fails, the old policies remain active.

### cedar-local-agent approach

AWS's `cedar-local-agent` crate provides built-in hot reload:

```rust
// File-based SHA256 change detection
let (signal_thread, receiver) = file_inspector_task(
    "policies/",
    RefreshRate::FifteenSeconds,
);

// Or periodic clock-based refresh
let (signal_thread, receiver) = clock_ticker_task(
    RefreshRate::FifteenSeconds,
);

// Background update thread
let update_thread = update_provider_data_task(
    policy_set_provider.clone(),
    receiver,
);
```

Minimum 3 threads: main (serves requests), signaler (detects changes), receiver (swaps data).


## 5. Cedar Policy Store Patterns

### File-based (simplest, recommended for starting)

- Policies as `.cedar` files in a directory
- Entities as `.json` files
- Schema as `.cedarschema` or `.cedar.json` files
- Version controlled in git
- `cedar-local-agent` provides `file::PolicySetProvider` and `file::EntityProvider`
- Hot reload via file watcher or periodic SHA256 comparison

### Database-backed

- Store policies as rows: `id`, `policy_text`, `version`, `created_at`
- Load all policies into a `PolicySet` on startup and after change notifications
- Change detection via database triggers, polling, or CDC (change data capture)
- PostgreSQL `LISTEN/NOTIFY` for push-based reload signals
- Schema stored alongside policies

### S3/Object Storage

- Policies bundled as a tarball or directory in S3
- Periodic polling for new versions (etag-based change detection)
- Download, parse, validate, then atomic swap via `arc-swap`
- Works well with CI/CD pipelines that publish policy bundles
- OPAL (Open Policy Administration Layer from Permit.io) supports this pattern for both OPA and Cedar

### Redis-backed

- cedar-agent lists Redis as a planned store backend (not yet implemented as of last check)
- Useful for multi-instance PDP deployments sharing policy state
- Pub/Sub for real-time change notification across PDP instances

### Hybrid: Git + file watcher

- Git repository as source of truth
- Webhook triggers `git pull` on PDP host
- File watcher detects changes, triggers reload
- Provides audit trail (git log) and rollback (git revert)


## 6. Kong-to-PDP Connection Patterns

### Kong's built-in OPA plugin (HTTP/JSON)

Kong has a native OPA plugin that sends authorization requests as HTTP POST with JSON:

```json
{
    "input": {
        "request": {
            "http": {
                "host": "example.org",
                "port": "8000",
                "method": "GET",
                "scheme": "http",
                "path": "/api/v1/users",
                "querystring": {},
                "headers": {
                    "authorization": "Bearer eyJ..."
                }
            }
        },
        "client_ip": "127.0.0.1",
        "service": {...},
        "route": {...},
        "consumer": {...}
    }
}
```

Expected response: `{"result": true}` or `{"result": {"allow": true, "headers": {...}, "status": 200}}`

**Configuration fields:** `opa_host`, `include_service_in_opa_input`, `include_route_in_opa_input`, `include_consumer_in_opa_input`, `include_uri_captures_in_opa_input`.

### Custom plugin with HTTP (simplest integration)

- Write a Kong custom plugin (Lua or Go) that calls your PDP over HTTP
- PDP exposes AuthZen-compatible `POST /access/v1/evaluation`
- Map Kong request context to AuthZen subject/action/resource
- Parse JWT in Kong, pass claims as `subject.properties`
- ~1-5ms added latency for localhost HTTP call

### gRPC via Envoy ext-authz protocol (lowest latency)

If Kong sits behind or alongside Envoy (e.g., in a service mesh):
- Implement the Envoy `ext_authz` gRPC service in tonic
- Proto: `envoy.service.auth.v3.Authorization` with `Check` RPC
- Request includes full HTTP headers, path, method, source/destination
- Response: `OkHttpResponse` (allow) or `DeniedHttpResponse` (deny with status/headers)
- Sub-millisecond latency over Unix domain socket or localhost gRPC

### Unix domain socket (lowest possible latency)

- PDP listens on `/var/run/pdp.sock`
- Kong plugin connects via Unix socket
- Eliminates TCP overhead entirely
- ~0.1-0.5ms latency
- Requires PDP and Kong on same host/container

### Recommendation for Kong

Start with **HTTP/JSON using the OPA-compatible request format** -- Kong already has the OPA plugin. Make your Cedar PDP speak the same protocol:
1. Accept `POST /v1/data/{policy_path}` with `{"input": {...}}` body
2. Return `{"result": true/false}` or `{"result": {"allow": bool, ...}}`
3. Zero Kong plugin development required -- reuse the existing OPA plugin
4. Migrate to gRPC later if latency requirements demand it


## 7. Performance Optimization

### Policy evaluation caching

Cedar's `Authorizer.is_authorized()` is fast (microseconds for typical policy sets), but caching decisions can still help:

```rust
use moka::sync::Cache;
use std::time::Duration;

struct DecisionCache {
    cache: Cache<String, Decision>,
}

impl DecisionCache {
    fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(60))
                .build(),
        }
    }

    fn cache_key(principal: &str, action: &str, resource: &str) -> String {
        format!("{}:{}:{}", principal, action, resource)
    }
}
```

**Cache invalidation strategies:**
- TTL-based (simplest, 30-60 second window acceptable for most APIs)
- Policy-change-triggered (invalidate all on policy reload)
- Entity-change-triggered (invalidate entries for affected entities)
- Never cache `forbid` decisions (they may be temporary)

### Policy set slicing

Cedar automatically slices the policy set -- it only evaluates policies whose scope matches the request's principal/action/resource types. This is a built-in optimization described in the Cedar paper. For a policy set of 10,000 policies, only the ~5-20 relevant ones are actually evaluated.

### Entity caching with `arc-swap`

For entities that don't change per-request (group memberships, role hierarchies):

```rust
struct EntityCache {
    // Entities that rarely change (roles, groups, permissions)
    static_entities: ArcSwap<Entities>,
    // Per-request entity resolution
    entity_resolver: Box<dyn EntityResolver>,
}
```

Merge cached static entities with per-request dynamic entities before evaluation.

### Connection pooling

Not directly applicable to Cedar (it's an embedded library, not a network service). But relevant for:
- Database connections for entity resolution: use `deadpool` or `bb8`
- HTTP clients for upstream entity fetching: use `reqwest` with connection pooling
- gRPC channels: `tonic::transport::Channel` handles connection pooling internally

### Request-level parallelism

For batch authorization requests, evaluate multiple Cedar requests concurrently:

```rust
use tokio::task::JoinSet;

async fn batch_evaluate(requests: Vec<AuthzRequest>) -> Vec<Decision> {
    let mut set = JoinSet::new();
    for req in requests {
        set.spawn_blocking(move || {
            authorizer.is_authorized(&req.cedar_request, &policies, &entities)
        });
    }
    // Collect results...
}
```

`spawn_blocking` because Cedar evaluation is CPU-bound, not async.


## 8. The cedar-agent Project (Permit.io)

### What it is

`cedar-agent` (https://github.com/permitio/cedar-agent) is a standalone HTTP server that wraps the Cedar policy engine. Built by Permit.io in Rust.

### Architecture

- **HTTP server** on port 8180 (configurable)
- **In-memory stores** for policies, entities, and schema
- **REST API** for CRUD operations on all stores
- **Authorization endpoint** at `POST /v1/is_authorized`

### API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| PUT | `/v1/policies` | Create/update policies |
| GET | `/v1/policies` | List all policies |
| DELETE | `/v1/policies` | Remove policies |
| PUT | `/v1/data` | Create/update entity data |
| GET | `/v1/data` | List entities |
| DELETE | `/v1/data` | Remove entities |
| PUT | `/v1/schema` | Set Cedar schema |
| POST | `/v1/is_authorized` | Evaluate authorization request |
| GET | `/rapidoc` | API docs (RapiDoc) |
| GET | `/swagger-ui` | API docs (Swagger) |

### Configuration

- `CEDAR_AGENT_PORT` / `--port` (default: 8180)
- `CEDAR_AGENT_ADDR` / `--addr` (default: 127.0.0.1)
- `CEDAR_AGENT_AUTHENTICATION` / `--authentication`
- `CEDAR_AGENT_LOG_LEVEL` / `--log-level` (default: info)
- `--data`, `--policies`, `--schema` flags for initial file-based loading

### Is it a reference PDP?

Partially. It demonstrates the pattern of wrapping Cedar in an HTTP service with REST APIs for policy management. However:
- It is a **reference implementation**, not production-hardened
- No built-in hot-reload (policies are pushed via API)
- In-memory only (Redis planned but not implemented)
- No gRPC support
- No AuthZen compliance
- Good starting point to understand the pattern, not to deploy as-is

### OPAL integration

Permit.io's OPAL (Open Policy Administration Layer) can push policy and data updates to cedar-agent, similar to how it manages OPA. This provides the hot-reload and policy distribution layer that cedar-agent itself lacks.


## 9. Cedar Entity Resolution at Request Time

### The entity challenge

Cedar requires entities (principal, resource, and their relationships) to be passed with each authorization request. Unlike OPA (which has a built-in data store), Cedar is deliberately stateless -- the caller must supply all relevant entity data.

### Where entities come from

**Source 1: JWT claims (principal attributes)**
```rust
// Extract from JWT at Kong/gateway level, pass to PDP
let subject_properties = jwt.claims;
// Map to Cedar entity
let principal_entity = Entity::new(
    principal_uid,
    claims_to_cedar_attrs(subject_properties),
    group_membership_parents,
).unwrap();
```

**Source 2: Database lookup (resource attributes, group memberships)**
```rust
// PDP resolves entity data from its own database
async fn resolve_entities(
    principal_id: &str,
    resource_type: &str,
    resource_id: &str,
    db: &Pool,
) -> Entities {
    let user = db.get_user(principal_id).await;
    let groups = db.get_user_groups(principal_id).await;
    let resource = db.get_resource(resource_type, resource_id).await;
    // Build Cedar entities with parent relationships
    // ...
}
```

**Source 3: Cached entity hierarchy (roles, groups, org structure)**
- Load full role/group hierarchy on startup
- Cache in `ArcSwap<Entities>` for lock-free access
- Refresh periodically or on change notification
- Merge with per-request entities before evaluation

**Source 4: Request context (transient attributes)**
```rust
let context = Context::from_pairs(vec![
    ("ip_addr".to_string(), RestrictedExpression::new_string(client_ip)),
    ("mfa".to_string(), RestrictedExpression::new_bool(has_mfa)),
    ("timestamp".to_string(), RestrictedExpression::new_long(now)),
]);
```

### cedar-local-agent's EntityProvider trait

```rust
// Implement this trait for custom entity resolution
#[async_trait]
pub trait EntityProvider {
    async fn get_entities(
        &self,
        request: &Request,
    ) -> Result<Entities, EntityProviderError>;
}
```

The built-in `file::EntityProvider` reads from JSON files and caches. Custom implementations can fetch from databases, APIs, or caches.

### Recommended pattern for a PDP service

1. **Static entities** (group hierarchy, role definitions): Load on startup, cache in `ArcSwap`, refresh on change
2. **Principal attributes**: Accept from PEP in the request (from JWT or session store)
3. **Resource attributes**: Resolve via database lookup with connection pooling, cache with TTL
4. **Context**: Accept from PEP (IP, time, MFA status, etc.)

The PDP should not trust entity data from the PEP for security-critical attributes. The PEP provides hints (principal ID, resource ID), and the PDP resolves the authoritative entity data from its own sources.


## 10. Error Handling and Observability

### What the PDP should expose

**Health endpoints:**
- `GET /health/live` -- process is alive (always 200 if listening)
- `GET /health/ready` -- policies loaded, entity store accessible, ready for traffic
- `GET /health/startup` -- initial policy load complete

**Metrics (Prometheus format):**
```
# Decision counters
pdp_decisions_total{decision="allow"} 1234
pdp_decisions_total{decision="deny"} 567

# Latency histogram
pdp_evaluation_duration_seconds_bucket{le="0.001"} 1500
pdp_evaluation_duration_seconds_bucket{le="0.01"} 1780

# Policy store state
pdp_policies_loaded_total 42
pdp_policy_reload_total{status="success"} 10
pdp_policy_reload_total{status="failure"} 1
pdp_policy_last_reload_timestamp 1712534400

# Entity resolution
pdp_entity_resolution_duration_seconds_bucket{source="cache",...}
pdp_entity_resolution_duration_seconds_bucket{source="database",...}
pdp_entity_cache_hit_total 9500
pdp_entity_cache_miss_total 500

# Error tracking
pdp_evaluation_errors_total{type="policy_error"} 3
pdp_evaluation_errors_total{type="entity_error"} 1
```

**Structured logging (tracing crate):**
```rust
use tracing::{info, warn, instrument};

#[instrument(skip(policies, entities), fields(
    principal = %request.principal(),
    action = %request.action(),
    resource = %request.resource(),
))]
fn evaluate(request: &Request, policies: &PolicySet, entities: &Entities) -> Response {
    let response = authorizer.is_authorized(request, policies, entities);
    info!(
        decision = ?response.decision(),
        determining_policies = ?response.diagnostics().reason().collect::<Vec<_>>(),
        "authorization decision"
    );
    response
}
```

**Decision audit log:**
- Every decision should be logged with: principal, action, resource, decision, determining policies, timestamp, request ID
- cedar-local-agent emits OCSF (Open Cyber Security Format) tracing events
- Field-level redaction: do not log sensitive context fields (tokens, PII) by default
- Structured JSON logs for aggregation in ELK/Loki/etc.

**Error handling patterns:**
```rust
// PDP should default-deny on errors
match evaluate_authorization(request).await {
    Ok(response) => response,
    Err(PolicyError::ParseError(e)) => {
        warn!("Policy parse error: {}", e);
        AuthzResponse { decision: false, error: Some(e.to_string()) }
    }
    Err(EntityError::ResolutionFailed(e)) => {
        warn!("Entity resolution failed: {}", e);
        AuthzResponse { decision: false, error: Some("entity resolution failed".into()) }
    }
    Err(e) => {
        error!("Unexpected error: {}", e);
        AuthzResponse { decision: false, error: Some("internal error".into()) }
    }
}
```

**Fail-closed by default:** If the PDP cannot evaluate a request (missing entities, corrupt policies, internal error), deny the request. Never fail-open unless explicitly configured.


## 11. Open-Source Rust PDP Implementations and References

### cedar-agent (Permit.io)
- **URL:** https://github.com/permitio/cedar-agent
- **What:** HTTP server wrapping Cedar with REST APIs for policy/entity management
- **Strengths:** Simple, well-documented API, Swagger/RapiDoc docs
- **Limitations:** In-memory only, no gRPC, no hot-reload, no AuthZen

### cedar-local-agent (AWS)
- **URL:** https://github.com/cedar-policy/cedar-local-agent
- **What:** Rust crate (library, not standalone server) providing async authorizer with pluggable providers
- **Strengths:** File-based policy/entity providers with caching, hot-reload via file watchers, OCSF audit logging, configurable field redaction
- **Limitations:** Library only (you build the server), file-based providers only out of the box

### cedar-for-agents (AWS)
- **URL:** https://github.com/cedar-policy/cedar-for-agents
- **What:** Cedar integration for AI agent authorization (newer, at intersection of Cedar + agents)
- **Contains:** Rust code and JS MCP server for Cedar analysis

### OPAL + cedar-agent (Permit.io)
- **URL:** https://github.com/permitio/opal-cedar
- **What:** Tutorial for running Cedar with OPAL for policy and data distribution
- **Pattern:** OPAL server manages policy lifecycle, pushes updates to cedar-agent instances

### OpenClaw Cedar PDP integration
- **URL:** https://github.com/windley/openclaw-cedar-policy-demo
- **What:** Cedar PDP client for AI agent tool authorization
- **Pattern:** External Cedar PDP with HTTP `/authorize` endpoint, PEP in agent execution loop

### OPA ext-authz examples (architecture reference)
- **URL:** https://github.com/pvsone/opa-ext-authz
- **What:** OPA as external authorizer for Kong, Istio, Envoy, Contour, Kuma
- **Relevance:** Same architectural patterns apply to a Cedar PDP -- swap OPA for Cedar

### MCP Context Forge PDP proposal
- **URL:** https://github.com/IBM/mcp-context-forge/issues/2223
- **What:** Design for unified PDP abstraction supporting Cedar, OPA, native RBAC, MAC
- **Pattern:** Single `PolicyDecisionPoint` interface with engine-specific adapters


## Architecture Recommendation

```
                    +-------------------+
                    |   Kong Gateway    |
                    | (OPA plugin or    |
                    |  custom plugin)   |
                    +--------+----------+
                             | HTTP POST /v1/data/authz/allow
                             | {"input": {request, consumer, ...}}
                             v
                    +-------------------+
                    |   Rust PDP        |
                    |   (axum + tonic)  |
                    |                   |
                    | /v1/data/...      | <-- OPA-compatible endpoint
                    | /access/v1/eval   | <-- AuthZen endpoint
                    | /admin/reload     | <-- Admin API
                    | /health/*         | <-- Health checks
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

**Key crates:**
```toml
[dependencies]
cedar-policy = "4.4"
axum = "0.8"
tonic = { version = "0.12", features = ["tls"] }
tokio = { version = "1", features = ["full"] }
arc-swap = "1.7"
notify = "7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
metrics = "0.24"
metrics-exporter-prometheus = "0.16"
moka = { version = "0.12", features = ["sync"] }
deadpool-postgres = "0.14"    # if using PostgreSQL for entities
```


## Sources

- [cedar-policy crate API docs](https://docs.rs/cedar-policy/latest/cedar_policy/)
- [cedar-policy crate Authorizer](https://docs.rs/cedar-policy/latest/cedar_policy/struct.Authorizer.html)
- [cedar-local-agent GitHub](https://github.com/cedar-policy/cedar-local-agent)
- [cedar-agent (Permit.io) GitHub](https://github.com/permitio/cedar-agent)
- [cedar-for-agents GitHub](https://github.com/cedar-policy/cedar-for-agents)
- [Cedar Policy Language Reference -- Authorization](https://docs.cedarpolicy.com/auth/authorization.html)
- [Cedar Policy Language Reference -- Design Patterns](https://docs.cedarpolicy.com/overview/patterns.html)
- [Cedar academic paper (Amazon Science)](https://assets.amazon.science/96/a8/1b427993481cbdf0ef2c8ca6db85/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization.pdf)
- [AWS Blog: cedar-local-agent and avp-local-agent](https://aws.amazon.com/blogs/opensource/easier-cedar-policy-management/)
- [AuthZen Authorization API 1.0 Deep Dive](https://dev.to/kanywst/authzen-authorization-api-10-deep-dive-the-standard-api-that-separates-authorization-decisions-1m2a)
- [OpenID AuthZen specification](https://openid.net/specs/authorization-api-1_0.html)
- [Authorization with Cedar in Rust tutorial](https://jun.codes/blog/authorization-with-cedar)
- [Cedarland Blog -- Partial Evaluation](https://cedarland.blog/usage/partial-evaluation/content.html)
- [Kong OPA Plugin docs](https://developer.konghq.com/plugins/opa/)
- [Kong + OPA authorization integration (Curity)](https://curity.io/resources/learn/curity-opa-kong-api/)
- [OPA-Envoy ext-authz plugin](https://openpolicyagent.org/docs/envoy)
- [OPA ext-authz examples repo](https://github.com/pvsone/opa-ext-authz)
- [Hot Configuration Reloading in Rust](https://oneuptime.com/blog/post/2026-01-25-hot-configuration-reloading-rust/view)
- [arc-swap crate docs](https://docs.rs/arc-swap)
- [arc-swap performance docs](https://docs.rs/arc-swap/latest/arc_swap/docs/performance/index.html)
- [axum_tonic crate docs](https://docs.rs/axum_tonic)
- [gRPC Basics for Rust Developers](https://dockyard.com/blog/2025/04/08/grpc-basics-for-rust-developers)
- [Building gRPC Services in Rust](https://oneuptime.com/blog/post/2026-01-08-grpc-rust-services/view)
- [Combining Axum, Hyper, Tonic, Tower](https://academy.fpblock.com/blog/axum-hyper-tonic-tower-part1/)
- [Scaling Authorization with Cedar and OPAL (Permit.io)](https://www.permit.io/blog/scaling-authorization-with-cedar-and-opal)
- [OPAL-Cedar tutorial](https://github.com/permitio/opal-cedar)
- [OpenClaw Cedar PDP demo](https://github.com/windley/openclaw-cedar-policy-demo)
- [Unified PDP proposal (IBM MCP Context Forge)](https://github.com/IBM/mcp-context-forge/issues/2223)
- [Permit.io PDP overview](https://docs.permit.io/concepts/pdp/overview)
- [ReBAC and ABAC: OpenFGA vs Cedar (Auth0)](https://auth0.com/blog/rebac-abac-openfga-cedar/)
- [Istio External Authorization](https://preliminary.istio.io/latest/blog/2021/better-external-authz/)
- [Cloudflare ecdysis: graceful restarts for Rust services](https://blog.cloudflare.com/ecdysis-rust-graceful-restarts/)
