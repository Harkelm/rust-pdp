---
source: web-research
date: 2026-04-08
project: rust-pdp
tags: [kong, plugin, api-gateway, authorization, external-plugin]
---

# Kong API Gateway Plugin Architecture for External Authorization

Research into Kong plugin internals, external plugin protocols, and deployment
patterns for building a Kong plugin that calls an external Rust PDP (Cedar policy
evaluation) and enforces allow/deny decisions.

---

## 1. Plugin Execution Phases

Kong processes requests through a pipeline of phases. Plugins hook into specific
phases to implement their logic. The phases execute in this order:

| Phase | When | Use Case |
|-------|------|----------|
| `init_worker` | Nginx worker startup | One-time initialization per worker |
| `configure` | Plugin iterator rebuild (v3.4+) | React to config changes |
| `certificate` | TLS handshake | mTLS, cert selection |
| `rewrite` | Before router executes | Global-only pre-routing transforms |
| `access` | After routing, before proxy | **Authentication, authorization, rate limiting** |
| `response` | After upstream response (buffered mode) | Full response inspection |
| `header_filter` | Response headers received | Modify response headers |
| `body_filter` | Response body chunks | Transform response body |
| `log` | After last byte sent to client | Logging, analytics |

**For an authorization plugin, the `access` phase is the correct phase.** This is
where all built-in auth plugins run. The access phase:

- Executes after the router has identified the matched service/route
- Runs before the request is proxied to the upstream
- Has full PDK access to request headers, path, method, query, body
- Can short-circuit the request with `kong.response.exit(status, body, headers)`
- Has access to consumer identity (if an auth plugin ran before it)

### Phase Handler Signatures

Lua:
```lua
local MyPlugin = {
  VERSION = "1.0.0",
  PRIORITY = 1000  -- higher = runs earlier
}

function MyPlugin:access(config)
  -- authorization logic here
  -- kong.response.exit(403, '{"error":"denied"}') to reject
end

return MyPlugin
```

Go:
```go
func (conf *MyConfig) Access(kong *pdk.PDK) {
    // authorization logic here
    // kong.Response.Exit(403, []byte(`{"error":"denied"}`), headers)
}
```

### Plugin Priority Values (Built-in Auth Plugins)

| Plugin | Priority |
|--------|----------|
| JWT | 1450 |
| OAuth 2.0 | 1400 |
| Key Auth | 1250 |
| Basic Auth | 1100 |
| HMAC Auth | 1030 |
| LDAP Auth | 1000 |
| ACL | 950 |
| Rate Limiting | 910 |
| OPA | Not documented precisely; enterprise plugin |

An authorization plugin should run AFTER authentication (to have consumer identity
available) but BEFORE other processing. A priority in the 900-1000 range (after
auth plugins, before rate limiting) is typical for authorization/ACL plugins.

### Dynamic Plugin Ordering (Enterprise)

Kong Enterprise supports overriding the static priority order per-plugin-instance
via the `ordering` field. This allows reordering plugins within the access phase
without changing their compiled priority values.

---

## 2. External Plugin Protocol (Non-Lua Plugins)

Kong supports plugins in Go, Python, JavaScript, and (experimentally) Rust. These
run as **external processes** that communicate with Kong over a local Unix domain
socket using an RPC protocol.

### Architecture

```
                    Unix socket
  Kong (Nginx) <===================> Plugin Server Process
  (Lua core)      RPC protocol       (Go/Python/JS/Rust)
```

- Kong manages the plugin server lifecycle (start, stop, restart)
- Each plugin compiles to a standalone executable
- The executable runs an embedded RPC server
- Communication is local-only (Unix domain socket, not network)

### RPC Protocol Options

| Language | Protocol | Library |
|----------|----------|---------|
| Go | MessagePack-RPC (historically); now embedded server with protobuf | `github.com/Kong/go-pdk` |
| Python | MessagePack-RPC | `kong-python-pdk` |
| JavaScript | MessagePack-RPC | `kong-js-pdk` |
| Rust | Protocol Buffers (protobuf via prost + tokio) | `kong-rust-pdk` (experimental) |

### Plugin Server Configuration (kong.conf)

```
pluginserver_names = my-authz-plugin

pluginserver_my_authz_plugin_socket = /usr/local/kong/my-authz-plugin.socket
pluginserver_my_authz_plugin_start_cmd = /usr/local/bin/my-authz-plugin
pluginserver_my_authz_plugin_query_cmd = /usr/local/bin/my-authz-plugin -dump

plugins = bundled,my-authz-plugin
```

### Key Constraint

External plugin servers communicate **only over local Unix domain sockets** (not
TCP). The plugin server process must run on the same host as Kong. This is a
hard constraint in the current implementation.

---

## 3. Go Plugin Development (Recommended Path)

Go plugins are the most mature external plugin option. Since Kong 3.0, they use
an **embedded server** model (each plugin is its own process with a built-in
RPC server), replacing the older `go-pluginserver` approach.

### Minimum Requirements

- Kong Gateway 3.4+
- Go PDK: `github.com/Kong/go-pdk` (v0.11.2 as of July 2025)
- NOT compatible with Konnect (cloud)

### Complete Plugin Structure

```go
package main

import (
    "github.com/Kong/go-pdk"
    "github.com/Kong/go-pdk/server"
)

const Version = "1.0.0"
const Priority = 950  // After auth plugins, before rate limiting

type Config struct {
    PdpHost    string `json:"pdp_host"`
    PdpPort    int    `json:"pdp_port"`
    PdpPath    string `json:"pdp_path"`
    Timeout    int    `json:"timeout_ms"`
}

func New() interface{} {
    return &Config{}
}

func (conf *Config) Access(kong *pdk.PDK) {
    // 1. Extract request context
    method, _ := kong.Request.GetMethod()
    path, _ := kong.Request.GetPath()
    headers, _ := kong.Request.GetHeaders(100)

    // 2. Get consumer identity (set by upstream auth plugin)
    consumer, err := kong.Client.GetConsumer()

    // 3. Call external PDP
    // (use net/http or gRPC client to call Rust PDP)

    // 4. Enforce decision
    if !allowed {
        kong.Response.Exit(403, []byte(`{"error":"access denied"}`),
            map[string][]string{"Content-Type": {"application/json"}})
        return
    }
}

func main() {
    server.StartServer(New, Version, Priority)
}
```

### Compilation and Deployment

```bash
go build -o cedar-authz-plugin
chmod +x cedar-authz-plugin
cp cedar-authz-plugin /usr/local/bin/
```

### Available Phase Handlers for Go Plugins

- `Certificate(kong *pdk.PDK)`
- `Rewrite(kong *pdk.PDK)`
- `Access(kong *pdk.PDK)` -- primary handler for authz
- `Response(kong *pdk.PDK)` -- enables buffered proxy mode automatically
- `Preread(kong *pdk.PDK)` -- for stream/TCP plugins
- `Log(kong *pdk.PDK)`

---

## 4. Request Context Available in Plugins

### Go PDK Request Module (`kong.Request`)

```go
GetScheme() (string, error)
GetHost() (string, error)
GetPort() (int, error)
GetForwardedScheme() (string, error)
GetForwardedHost() (string, error)
GetForwardedPort() (int, error)
GetMethod() (string, error)           // "GET", "POST", etc.
GetPath() (string, error)             // "/api/v1/resource"
GetPathWithQuery() (string, error)    // "/api/v1/resource?key=val"
GetRawQuery() (string, error)         // "key=val&other=2"
GetQuery(max int) (map[string][]string, error)
GetQueryArg(key string) (string, error)
GetHeader(key string) (string, error)
GetHeaders(max int) (map[string][]string, error)
GetRawBody() ([]byte, error)
GetUriCaptures() ([][]byte, map[string][]byte, error)  // regex captures
```

### Go PDK Client Module (`kong.Client`)

```go
GetIp() (string, error)               // Direct client IP
GetForwardedIp() (string, error)      // Respects X-Forwarded-For
GetPort() (int, error)
GetForwardedPort() (int, error)
GetConsumer() (entities.Consumer, error)  // Authenticated consumer
GetCredential() (AuthenticatedCredential, error)  // Credential used
Authenticate(consumer, credential) error  // Set auth identity
LoadConsumer(id string, byUsername bool) (entities.Consumer, error)
GetProtocol(allowTerminated bool) (string, error)
```

### Go PDK Response Module (`kong.Response`)

```go
GetStatus() (int, error)
GetHeader(name string) (string, error)
GetHeaders(max int) (map[string][]string, error)
GetSource() (string, error)           // "exit", "error", or "service"
SetStatus(status int) error
SetHeader(key, value string) error
AddHeader(key, value string) error
ClearHeader(key string) error
SetHeaders(headers map[string][]string) error
Exit(status int, body []byte, headers map[string][]string)
ExitStatus(status int)
```

### AuthenticatedCredential Struct

```go
type AuthenticatedCredential struct {
    Id         string `json:"id"`
    ConsumerId string `json:"consumer_id"`
}
```

### JWT Claims Access

JWT claims are NOT directly available through the PDK. The JWT plugin validates
tokens and sets the consumer identity, but decoded claims are typically passed
as headers to the upstream. To access JWT claims in an authorization plugin:

1. Read the `Authorization: Bearer <token>` header via `kong.Request.GetHeader("Authorization")`
2. Decode the JWT yourself (the token has already been validated by the JWT plugin)
3. Or configure the JWT plugin to forward claims as headers, then read those headers

### Consumer Identity

After an auth plugin runs (key-auth, jwt, oauth2, etc.), the consumer entity
is available via `kong.Client.GetConsumer()`. The consumer contains:
- ID (UUID)
- Username
- Custom ID
- Associated credentials

---

## 5. Built-in Auth Plugin Patterns

All Kong auth plugins follow the same architectural pattern:

### Common Flow

```
1. Extract credentials (header, query param, body, cookie)
2. Validate credentials against Kong datastore/cache
3. On success: set kong.authenticated_consumer + kong.authenticated_credential
4. On failure: return 401/403 or fall back to anonymous consumer
```

### Key Configuration Patterns

| Option | Purpose |
|--------|---------|
| `anonymous` | Consumer ID/username for fallback when auth fails |
| `hide_credentials` | Strip credentials before forwarding to upstream |
| `realm` | WWW-Authenticate header value |

### Multiple Auth Plugin Behavior

- **Without `anonymous`**: ALL auth plugins must succeed (AND logic)
- **With `anonymous`**: First successful plugin wins; if all fail, anonymous consumer is used (OR logic)

### ACL Plugin (Authorization Layer)

The ACL plugin runs AFTER authentication (priority 950 vs auth plugins at 1000+).
It checks consumer group membership against allow/deny lists. This is the
separation of concerns pattern: auth plugins answer "who are you?", ACL/OPA
answer "what can you do?".

Our Cedar PDP plugin follows the same pattern: it should run after auth plugins
set the consumer identity, then call the PDP with the consumer + request context.

---

## 6. Kong OPA Plugin Architecture (Closest Analog)

The OPA plugin is the closest architectural analog to our Cedar PDP plugin. It
is a **Kong Enterprise** feature (not open-source).

### How It Works

1. Plugin runs in the **access phase**
2. Constructs a JSON input object from the request context
3. Makes an HTTP POST to the OPA server at `{opa_protocol}://{opa_host}:{opa_port}{opa_path}`
4. OPA evaluates the request against its Rego policies
5. Based on the response, Kong allows or denies the request

### OPA Input Structure

```json
{
  "input": {
    "request": {
      "http": {
        "method": "GET",
        "scheme": "https",
        "host": "api.example.com",
        "port": 443,
        "path": "/api/v1/resource",
        "headers": { "authorization": "Bearer ..." },
        "querystring": { "key": "value" }
      }
    },
    "client_ip": "10.0.0.1",
    "service": { ... },       // if include_service_in_opa_input = true
    "route": { ... },         // if include_route_in_opa_input = true
    "consumer": { ... }       // if include_consumer_in_opa_input = true
  }
}
```

### OPA Response Handling

**Boolean mode**: OPA returns `{"result": true}` or `{"result": false}`

**Object mode** (richer):
```json
{
  "result": {
    "allow": true,
    "headers": { "X-Custom": "value" },
    "status": 403,
    "message": "Access denied: insufficient permissions"
  }
}
```

- `result.allow` (boolean, required): allow or deny
- `result.headers` (object, optional): injected into request (if allowed) or response (if denied)
- `result.status` (integer, optional): HTTP status on deny, defaults to 403
- `result.message` (string, optional): response body on deny, defaults to "unauthorized"

### Full OPA Plugin Configuration Schema

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `opa_host` | string | `"localhost"` | No | OPA server hostname |
| `opa_port` | integer | `8181` | No | OPA server port (0-65535) |
| `opa_protocol` | enum | `"http"` | No | `"http"` or `"https"` |
| `opa_path` | string | -- | **Yes** | URL path to policy endpoint (must start with `/`) |
| `ssl_verify` | boolean | `true` | No | Verify OPA TLS certificate |
| `include_body_in_opa_input` | boolean | `false` | No | Include raw request body |
| `include_parsed_json_body_in_opa_input` | boolean | `false` | No | JSON-decode body when Content-Type is application/json |
| `include_consumer_in_opa_input` | boolean | `false` | No | Include Kong Consumer entity |
| `include_service_in_opa_input` | boolean | `false` | No | Include Kong Service entity |
| `include_route_in_opa_input` | boolean | `false` | No | Include Kong Route entity |
| `include_uri_captures_in_opa_input` | boolean | `false` | No | Include regex capture groups from route |

### Error Handling

If OPA returns a non-200 status or unexpected response format, the plugin returns
500 Internal Server Error to the client. This is important for our design: we
need a clear failure mode when the PDP is unreachable.

### Design Lessons for Cedar PDP Plugin

Our plugin should mirror this pattern:
1. Configurable PDP endpoint (host, port, protocol, path)
2. Selectable input enrichment (consumer, service, route, body)
3. Clear allow/deny response contract
4. Configurable deny status code and message
5. 500 on PDP communication failure (fail-closed)

---

## 7. Latency and Performance

### External Plugin Overhead (Kong Process <-> Plugin Server)

Benchmark data from Kong 3.2.2 (GitHub Discussion #10823):

| Metric | No Plugin | Empty Go Plugin | Delta |
|--------|-----------|-----------------|-------|
| Requests/sec | 1,738 | 1,298 | **-25%** |
| Avg Latency | 1.21ms | 1.55ms | **+0.34ms** |
| P99 Latency | 4.35ms | 3.06ms | (P99 improved due to lower throughput) |

The **25% throughput reduction** comes purely from Unix socket IPC between Kong
and the Go plugin process, even with empty handlers. This is the floor cost of
using any external plugin.

Key finding from Kong maintainers: "If performance matters and your plugin is a
hot path, Lua is really the only option."

### Additional PDP Call Overhead

On top of the external plugin IPC cost, our plugin adds an HTTP/gRPC call to the
Rust PDP. Estimated total added latency per request:

| Component | Estimated Latency |
|-----------|-------------------|
| Kong <-> Go plugin (IPC) | ~0.3-0.5ms |
| Go plugin <-> Rust PDP (HTTP/gRPC, sidecar) | ~1-3ms |
| Cedar policy evaluation in PDP | ~0.1-1ms (Cedar is designed for <1ms) |
| **Total added latency** | **~1.5-5ms per request** |

For comparison, Permit.io reports 1-5ms for their PDP sidecar authorization
decisions.

### Mitigation Strategies

1. **Sidecar deployment**: Run PDP on same host/pod as Kong (localhost, no network hop)
2. **gRPC over HTTP**: Use gRPC for plugin<->PDP communication (lower overhead than HTTP/JSON)
3. **Connection pooling**: Maintain persistent connections to PDP
4. **Lua plugin option**: If latency is critical, write the PDP call as a Lua plugin using `lua-resty-http` (cosocket-based, non-blocking) to eliminate IPC overhead
5. **Caching**: Cache authorization decisions for identical (principal, action, resource) tuples

---

## 8. Plugin Configuration Scoping

Kong plugins can be applied at multiple levels, with fine-grained precedence.

### Scope Levels

| Scope | Description |
|-------|-------------|
| Global | All requests, all services, all routes |
| Service | All routes belonging to a specific service |
| Route | A specific route only |
| Consumer | Requests from a specific authenticated consumer |
| Consumer Group | Requests from consumers in a group |

### Precedence Order (Highest to Lowest)

1. Consumer + Route + Service
2. Consumer Group + Service + Route
3. Consumer + Route
4. Consumer + Service
5. Consumer Group + Route
6. Consumer Group + Service
7. Route + Service
8. Consumer
9. Consumer Group
10. Route
11. Service
12. Global

### Admin API Configuration

```bash
# Global
curl -X POST http://localhost:8001/plugins \
  --data "name=cedar-authz" \
  --data "config.pdp_host=localhost" \
  --data "config.pdp_port=8180"

# Per-service
curl -X POST http://localhost:8001/services/{service-id}/plugins \
  --data "name=cedar-authz" \
  --data "config.pdp_host=localhost"

# Per-route
curl -X POST http://localhost:8001/routes/{route-id}/plugins \
  --data "name=cedar-authz" \
  --data "config.pdp_host=localhost"
```

### Design Implication

Our Cedar plugin should support per-route and per-service configuration to allow
different policy paths or PDP endpoints per API. The configuration struct in Go
maps directly to what the admin API accepts as `config.*` fields.

---

## 9. PDK API Summary for Authorization Plugins

### Lua PDK Modules (Complete List)

| Module | Purpose |
|--------|---------|
| `kong.request` | Read incoming request (headers, path, method, query, body) |
| `kong.response` | Set/modify response, exit with status |
| `kong.service` | Service entity info |
| `kong.service.request` | Modify request to upstream |
| `kong.service.response` | Read upstream response |
| `kong.client` | Client IP, consumer, credential, authenticate |
| `kong.client.tls` | TLS client info |
| `kong.ctx` | Per-request shared context between plugins |
| `kong.log` | Logging (debug, info, warn, err, crit) |
| `kong.router` | Route matching info |
| `kong.ip` | Trusted IP checking |
| `kong.node` | Node-level info |
| `kong.cache` | Database entity caching |
| `kong.vault` | Secrets management |
| `kong.telemetry.log` | OpenTelemetry integration |
| `kong.tracing` | Distributed tracing |

### Critical PDK Calls for an Authz Plugin

```go
// Read request context
method, _ := kong.Request.GetMethod()        // "GET", "POST", etc.
path, _ := kong.Request.GetPath()            // "/api/v1/users/123"
headers, _ := kong.Request.GetHeaders(100)   // all headers
query, _ := kong.Request.GetQuery(100)       // query parameters
body, _ := kong.Request.GetRawBody()         // request body bytes
scheme, _ := kong.Request.GetScheme()        // "https"
host, _ := kong.Request.GetHost()            // "api.example.com"

// Read client/consumer identity
ip, _ := kong.Client.GetIp()                // "10.0.0.1"
consumer, _ := kong.Client.GetConsumer()     // entities.Consumer struct
cred, _ := kong.Client.GetCredential()       // AuthenticatedCredential

// Deny the request
kong.Response.Exit(403, []byte(`{"error":"denied by policy"}`),
    map[string][]string{
        "Content-Type": {"application/json"},
        "X-Cedar-Decision": {"deny"},
    })

// Allow: just return from the handler without calling Exit
```

### Shared Context Between Plugins

The `kong.Ctx` module allows plugins to share data within a single request.
An auth plugin can store decoded JWT claims in the context, and our authz plugin
can read them:

```lua
-- In auth plugin
kong.ctx.shared.jwt_claims = decoded_claims

-- In authz plugin
local claims = kong.ctx.shared.jwt_claims
```

The Go PDK `kong.Ctx` provides `SetShared(key, value)` and `GetSharedString(key)`.

---

## 10. Deployment Considerations

### Sidecar vs. Remote PDP

| Pattern | Latency | Availability | Operations |
|---------|---------|--------------|------------|
| **Sidecar** (same pod/host) | 1-3ms | Tied to gateway lifecycle | Simpler, co-deployed |
| **Remote** (separate service) | 3-10ms+ | Independent scaling | More complex, needs network |
| **Embedded** (in-plugin) | <1ms | No external dep | Cedar Rust linked into Go via CGO? Complex |

**Recommendation**: Sidecar deployment. Run the Rust PDP as a container in the
same pod (Kubernetes) or on the same host as Kong. This gives:
- Localhost networking (no cross-network latency)
- Co-located lifecycle management
- Simple failure domain (pod restart restarts both)

### Connection Pooling

**For Lua plugins**: Use `lua-resty-http` with `set_keepalive()`. The cosocket
connection pool is per-worker, with configurable max idle timeout and pool size.
```lua
httpc:set_keepalive(60000, 100)  -- 60s idle timeout, 100 pool size per worker
```

**For Go plugins**: Use Go's standard `net/http` client with `Transport`
connection pooling:
```go
transport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 100,
    IdleConnTimeout:     90 * time.Second,
}
client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
```

Since the Go plugin is a long-running process, a package-level `http.Client`
maintains connection pools across requests.

### Circuit Breaking

Kong does not provide built-in circuit breaking for plugin HTTP calls. Options:

1. **Community plugin**: `dream11/kong-circuit-breaker` wraps upstream proxy calls
   with circuit breaker (open/half-open/closed states). But this applies to the
   upstream, not to plugin-internal HTTP calls.

2. **In-plugin circuit breaker**: Implement in the Go plugin using a library like
   `sony/gobreaker` or `afex/hystrix-go`. The circuit breaker wraps PDP calls:
   - **Closed**: Normal operation, requests go to PDP
   - **Open**: PDP failures exceeded threshold, fail-open or fail-closed
   - **Half-open**: Periodically test PDP availability

3. **Timeout-based degradation**: Set aggressive timeouts (50-100ms) on PDP calls.
   If PDP is slow/down, the timeout triggers and the plugin either denies (fail-closed)
   or allows (fail-open) based on configuration.

### Fail-Open vs. Fail-Closed

This is a policy decision:
- **Fail-closed** (deny on PDP failure): More secure, but PDP outage = total API outage
- **Fail-open** (allow on PDP failure): Less secure, but PDP outage does not block traffic
- **Configurable**: Best approach. Default to fail-closed, allow per-route override

### Health Checking

The Go plugin should implement a health check against the PDP on startup and
periodically. If PDP is unreachable at startup, log a warning but don't crash
the plugin server (that would block Kong from starting).

---

## Appendix A: Kong Rust PDK (Experimental)

There is an unofficial Rust PDK at `github.com/jgramoll/kong-rust-pdk`:

- Uses protobuf (prost) for communication with Kong
- Async/await via tokio
- 14 commits, 21 stars, 3 forks -- very low adoption
- No official releases
- **Not recommended for production**

This means writing the Kong plugin itself in Rust is not viable. The recommended
approach is:
1. Write the **Kong plugin in Go** (mature PDK, embedded server, good ecosystem)
2. The Go plugin calls the **Rust PDP** over HTTP/gRPC
3. The Rust PDP evaluates Cedar policies and returns allow/deny

Alternatively, for maximum performance:
1. Write the **Kong plugin in Lua** using `lua-resty-http`
2. The Lua plugin calls the Rust PDP via HTTP (cosocket-based, non-blocking)
3. Eliminates the ~0.3-0.5ms IPC overhead of external plugins

### Appendix B: Lua Plugin Alternative (Performance Path)

If the 25% throughput reduction from Go plugin IPC is unacceptable, a Lua plugin
that calls the PDP via HTTP is the performance path:

```lua
local http = require "resty.http"

local MyAuthzPlugin = {
  VERSION = "1.0.0",
  PRIORITY = 950,
}

function MyAuthzPlugin:access(config)
  local httpc = http.new()
  httpc:set_timeout(config.timeout_ms)

  local res, err = httpc:request_uri(
    config.pdp_url .. config.pdp_path,
    {
      method = "POST",
      body = cjson.encode({
        principal = kong.client.get_consumer(),
        action = kong.request.get_method(),
        resource = kong.request.get_path(),
        context = {
          headers = kong.request.get_headers(),
          query = kong.request.get_query(),
          ip = kong.client.get_ip(),
        },
      }),
      headers = {
        ["Content-Type"] = "application/json",
      },
      keepalive_timeout = 60000,
      keepalive_pool = 100,
    }
  )

  if not res or res.status ~= 200 then
    return kong.response.exit(500, '{"error":"PDP unreachable"}')
  end

  local decision = cjson.decode(res.body)
  if not decision.allow then
    return kong.response.exit(
      decision.status or 403,
      cjson.encode({ error = decision.message or "access denied" }),
      { ["Content-Type"] = "application/json" }
    )
  end
end

return MyAuthzPlugin
```

This runs entirely in-process with Kong (no IPC overhead) and uses cosocket-based
non-blocking HTTP, which integrates with Nginx's event loop.

---

## Appendix C: Decision Matrix

| Approach | Plugin Language | PDP Communication | IPC Overhead | PDP Latency | Total | Maturity |
|----------|----------------|-------------------|--------------|-------------|-------|----------|
| A: Go plugin + HTTP PDP | Go | HTTP/JSON | ~0.3-0.5ms | ~1-3ms | ~2-4ms | High (go-pdk v0.11) |
| B: Go plugin + gRPC PDP | Go | gRPC/protobuf | ~0.3-0.5ms | ~0.5-2ms | ~1-3ms | High |
| C: Lua plugin + HTTP PDP | Lua | HTTP/JSON | 0ms (in-process) | ~1-3ms | ~1-3ms | High (native) |
| D: Rust plugin + embedded | Rust | In-process | 0ms | <0.1ms | <0.1ms | Very Low (experimental) |

**Recommended**: Start with **Approach A** (Go plugin + HTTP PDP) for fastest
development. Migrate to **Approach C** (Lua plugin) if performance profiling
shows the IPC overhead matters. Approach B (gRPC) is an optimization within
the Go path.
