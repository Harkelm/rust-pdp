# Kong Plugin Architecture for External Authorization

Compiled from `knowledge/raw/2026-04-08-kong-plugin-architecture.md` on 2026-04-08.

## Overview

Kong processes requests through a phase pipeline. Authorization plugins hook into the
**access phase** -- after routing, before proxy. External plugins (Go, Python, JS) run
as separate processes communicating over Unix domain sockets via MessagePack-RPC or
protobuf. Go is the most mature external plugin option.

## Plugin Execution Phases

| Phase | When | Use Case |
|-------|------|----------|
| `init_worker` | Nginx worker startup | One-time initialization |
| `configure` | Plugin iterator rebuild (v3.4+) | React to config changes |
| `certificate` | TLS handshake | mTLS, cert selection |
| `rewrite` | Before router | Global pre-routing transforms |
| **`access`** | **After routing, before proxy** | **Auth, authz, rate limiting** |
| `response` | After upstream response | Full response inspection |
| `header_filter` | Response headers received | Modify response headers |
| `body_filter` | Response body chunks | Transform response body |
| `log` | After last byte sent | Logging, analytics |

## External Plugin Protocol

```
Kong (Nginx) <=== Unix socket ===> Plugin Server Process (Go/Python/JS)
```

- Kong manages the plugin server lifecycle
- Each plugin compiles to a standalone executable with embedded RPC server
- Communication is local-only (Unix domain socket, not TCP) -- hard constraint
- Plugin server must run on same host as Kong

### Plugin Server Configuration (kong.conf)

```
pluginserver_names = cedar-authz-plugin
pluginserver_cedar_authz_plugin_socket = /usr/local/kong/cedar-authz.socket
pluginserver_cedar_authz_plugin_start_cmd = /usr/local/bin/cedar-authz-plugin
pluginserver_cedar_authz_plugin_query_cmd = /usr/local/bin/cedar-authz-plugin -dump
plugins = bundled,cedar-authz-plugin
```

## Go Plugin Development (Recommended)

Minimum: Kong Gateway 3.4+, `github.com/Kong/go-pdk` v0.11.2+. Not Konnect-compatible.

### Plugin Structure

```go
package main

import (
    "github.com/Kong/go-pdk"
    "github.com/Kong/go-pdk/server"
)

const Version = "1.0.0"
const Priority = 950  // After auth plugins, before rate limiting

type Config struct {
    PdpHost string `json:"pdp_host"`
    PdpPort int    `json:"pdp_port"`
    Timeout int    `json:"timeout_ms"`
    FailOpen bool  `json:"fail_open"`
}

func New() interface{} { return &Config{} }

func (conf *Config) Access(kong *pdk.PDK) {
    method, _ := kong.Request.GetMethod()
    path, _ := kong.Request.GetPath()
    headers, _ := kong.Request.GetHeaders(100)
    consumer, _ := kong.Client.GetConsumer()
    // Call PDP, enforce decision
}

func main() { server.StartServer(New, Version, Priority) }
```

### Priority Values (Built-in Auth Plugins)

JWT: 1450, OAuth 2.0: 1400, Key Auth: 1250, Basic Auth: 1100, ACL: 950.
Authorization plugin should be 900-1000 range (after auth, before rate limiting).

## Request Context Available

### Key PDK Methods for Authorization

```go
// Request context
kong.Request.GetMethod()           // "GET", "POST"
kong.Request.GetPath()             // "/api/v1/resource"
kong.Request.GetHeaders(100)       // all headers
kong.Request.GetQuery(100)         // query parameters
kong.Request.GetRawBody()          // request body

// Client/consumer identity
kong.Client.GetIp()                // client IP
kong.Client.GetConsumer()          // authenticated consumer entity
kong.Client.GetCredential()        // credential used

// Response control
kong.Response.Exit(403, body, headers)  // deny request
// Allow: return from handler without calling Exit
```

### JWT Claims Access

JWT claims are NOT directly available through PDK. Options:
1. Read `Authorization: Bearer <token>` header, decode JWT yourself (already validated)
2. Configure JWT plugin to forward claims as headers
3. Use `kong.Ctx.GetSharedString(key)` if auth plugin stores claims in shared context

## OPA Plugin Architecture (Closest Analog)

Kong Enterprise has a native OPA plugin that mirrors our target pattern:

1. Runs in access phase
2. Constructs JSON input from request context
3. HTTP POST to OPA server with `{"input": {request, consumer, service, route}}`
4. OPA evaluates Rego policies, returns `{"result": true}` or richer object
5. Kong allows or denies based on response

**Key config fields**: `opa_host`, `opa_port`, `opa_path`, `include_consumer_in_opa_input`,
`include_service_in_opa_input`, `include_route_in_opa_input`.

Our Cedar PDP plugin follows the same pattern, replacing OPA with Cedar evaluation.

## Performance: External Plugin Overhead

Benchmark data (Kong 3.2.2):

| Metric | No Plugin | Empty Go Plugin | Delta |
|--------|-----------|-----------------|-------|
| Requests/sec | 1,738 | 1,298 | **-25%** |
| Avg Latency | 1.21ms | 1.55ms | **+0.34ms** |

The 25% throughput reduction is the floor cost of ANY external plugin (IPC overhead).

### Total Estimated Latency Budget

| Component | Latency |
|-----------|---------|
| Kong <-> Go plugin (IPC) | ~0.3-0.5ms |
| Go plugin <-> Rust PDP (HTTP, sidecar) | ~1-3ms |
| Cedar policy evaluation | ~0.1-1ms |
| **Total added** | **~1.5-5ms per request** |

### Mitigation Strategies

1. **Sidecar deployment**: PDP on same host/pod (localhost, no network hop)
2. **gRPC over HTTP**: Lower overhead than HTTP/JSON
3. **Connection pooling**: Persistent connections to PDP
4. **Lua plugin option**: Eliminates IPC overhead entirely (~0 vs ~0.3-0.5ms)
5. **Decision caching**: Cache (principal, action, resource) -> decision with TTL

## Deployment Patterns

| Pattern | Latency | Availability |
|---------|---------|--------------|
| **Sidecar** (same pod) | 1-3ms | Tied to gateway lifecycle |
| **Remote** (separate service) | 3-10ms+ | Independent scaling |
| **Embedded** (in-plugin) | <1ms | No external dep (complex) |

**Recommendation**: Sidecar deployment for localhost networking + co-located lifecycle.

## Plugin Approach Decision Matrix

| Approach | Plugin | PDP Communication | IPC Overhead | Total Latency | Maturity |
|----------|--------|-------------------|--------------|---------------|----------|
| A: Go + HTTP | Go | HTTP/JSON | ~0.3-0.5ms | ~2-4ms | High |
| B: Go + gRPC | Go | gRPC/protobuf | ~0.3-0.5ms | ~1-3ms | High |
| C: Lua + HTTP | Lua | HTTP/JSON | 0ms | ~1-3ms | High |
| D: Rust embedded | Rust | In-process | 0ms | <0.1ms | Very Low |

**Start with A** (Go + HTTP) for fastest development. Migrate to C (Lua) if IPC
overhead matters. Rust PDK is experimental (21 stars, 14 commits) -- not viable.

## Configuration Scoping

Plugins can be applied at: Global, Service, Route, Consumer, Consumer Group levels
with fine-grained precedence (12 levels). Our plugin should support per-route and
per-service configuration for different policy paths or PDP endpoints per API.

## Sources

- Kong External Plugins: docs.konghq.com
- Kong Go PDK: github.com/Kong/go-pdk
- Kong OPA Plugin: developer.konghq.com/plugins/opa/
- Kong performance discussion: GitHub #10823
