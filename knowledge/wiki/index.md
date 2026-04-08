# Rust PDP Knowledge Wiki

Project: External Cedar Policy Decision Point for Kong API Gateway

## Articles

- [Cedar Policy Language](cedar-policy-language.md) -- Language syntax, PARC model, evaluation semantics, Rust crate API, performance, limitations, comparison with OPA
- [Kong Plugin Architecture](kong-plugin-architecture.md) -- Phase pipeline, external plugin protocol, Go PDK, request context, OPA analog, latency budget, deployment patterns
- [Rust PDP Service Architecture](rust-pdp-service-architecture.md) -- axum+tonic stack, API design (Cedar-native + AuthZen), policy hot-reload (arc-swap), entity resolution, caching, observability
- [Entitlement Translation](entitlement-translation.md) -- Legacy RBAC/ABAC to Cedar entity model, JWT mapping, sync patterns, policy templates, six-phase migration methodology

## Domain Map

- **Cedar Policy Language**: Policy syntax, schema, evaluation semantics, Rust crate API
- **Kong Integration**: Plugin architecture, external plugin protocol, request context extraction
- **PDP Architecture**: Service design, gRPC/HTTP, policy loading, caching, observability
- **Entitlement Translation**: Legacy ACL/RBAC to Cedar entity model, migration patterns
- **Performance**: Latency budgets, benchmarks, optimization strategies
- **Risks**: Default-deny edge cases, policy consistency, migration regression
