# CLAUDE.md -- rust-pdp

## Project

External Rust PDP (Policy Decision Point) using Cedar for authorization in a Kong
API gateway. Evaluates JWT claims against Cedar policies with sub-millisecond latency.
This is a real work project for the team lead, not a learning exercise.

## Architecture

Rust (cedar-policy 4.x), axum HTTP server, arc-swap for lock-free policy hot-reload,
rayon for parallel batch evaluation. Two Kong plugin implementations (Lua primary,
Go reference). Production Cedar policies in `policies/`.

| Path | Purpose |
|------|---------|
| `pdp/src/` | Rust PDP service (main, handlers, avp, policy, entities, models) |
| `pdp/tests/` | Integration tests (security, policy coverage, concurrency, etc.) |
| `pdp/benches/` | Criterion benchmarks (cedar eval, batch throughput, entity construction, reload contention) |
| `policies/` | Production Cedar policies + schema |
| `kong-plugin-lua/` | Primary Kong plugin (Lua, zero IPC overhead) |
| `kong-plugin-go/` | Reference Go plugin (for comparison/migration) |
| `benchmarks/` | Docker-based HTTP load tests, Go vs Lua comparison |
| `docs/adr/` | Architecture Decision Records (ADR-001 through ADR-006) |
| `docs/roundtable/` | 9-panelist architecture review (RT-26) |
| `knowledge/wiki/` | Compiled research articles |

## Key Decisions

- **AVP format is primary**: `/avp/*` endpoints speak the Amazon Verified Permissions wire format natively. `/v1/*` is a legacy format with JWT claims auto-construction
- **ADR-001**: Lua plugin (not Go) -- measured 27x IPC overhead at concurrency 100
- **ADR-006**: Fail-closed, no FailOpen toggle. PDP error = 503+Retry-After, never 403
- **ADR-005**: Tiered entity model (Tier 1: JWT identity, Tier 2: required attrs, Tier 3: hierarchy)
- **Org-scoped policy**: Guard clause rejects empty/sentinel org values (defense in depth)

## Git Protocol

This is a **standalone git repo** (submodule of ccc at `projects/rust-pdp/`).

- Commit and push directly: `git commit <files> -m "msg" && git push origin main`
- Do NOT use `git add` -- another agent may be working here concurrently
- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `data:`
- After pushing, the ccc orchestrator updates the submodule pointer separately

## Concurrent Work

Multiple agents may work in this repo simultaneously. Safety rules:

- **Disjoint files only.** Two agents must not edit the same file. If your task
  overlaps with another agent's files, serialize (finish one before starting the other).
- **No worktree isolation.** EnterWorktree in the parent ccc repo does not create
  isolated copies of this submodule. There is one shared working tree.
- **Commit frequently.** Small commits reduce the conflict window. Commit after each
  working unit, not at the end of a session.
- **Check before writing.** If a file has unexpected changes (not from your session),
  another agent may be mid-edit. Read before writing. If in doubt, skip that file
  and note it in your handoff.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CEDAR_POLICY_DIR` | `./policies` | Policy/schema directory |
| `PDP_PORT` | `8180` | HTTP listen port |
| `PDP_ADMIN_TOKEN` | _(unset)_ | Bearer token for `/admin/reload` (dev mode if unset) |
| `RUST_LOG` | `cedar_pdp=info` | Tracing filter |

## Testing

```bash
cd pdp
cargo test                    # all unit + integration + stress tests (248 tests)
cargo bench                   # all Criterion benchmarks
cargo bench --bench cedar_eval  # specific benchmark group
cargo run --example memory_scaling --release  # heap measurement
```

Tests use production Cedar policies from `../policies/`. Integration tests spin up
an axum server on a random port per test. Most tests construct `AppContext::new(store, None)`
(no admin token) so admin endpoints are unrestricted in test mode. The `admin_auth.rs`
tests exercise both auth-enforced mode (`Some(token)`) and dev mode (`None`).

## Constraints

- No YAML. TOML for config, JSON for machine-generated data.
- No marketing terminology.
- Every claim must be verifiable (tested or sourced). No assumptions from training data.
- The AGI Accelerationist lens (scale-first thinking) is the default design perspective.
