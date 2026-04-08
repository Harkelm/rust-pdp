# ADR-004: Policy Hot-Reload Strategy

**Status**: Accepted  
**Date**: 2026-04-08  
**Source**: Architecture roundtable RT-26

## Decision

**arc-swap + file watcher (notify crate) with two required fixes.**

The arc-swap pattern provides lock-free reads on the hot path (every authorization
request) with atomic swap on reload. Validation-before-swap ensures broken policy
files never become active.

### Fix 1: Single tuple swap

The current design issues two sequential `store()` calls (PolicySet then Schema).
Between the two stores, a concurrent reader can see a new PolicySet with an old
Schema. While Cedar evaluation does not reference Schema at runtime (confirmed
during roundtable), the inconsistency window affects any code path that reads both
fields (admin endpoints, validation endpoints, future paths).

Fix: wrap both in a single `Arc<(PolicySet, Schema)>` behind one `ArcSwap`. One
swap, no torn reads possible.

### Fix 2: Cache wrapper on hot path

`ArcSwap::load()` touches the global reference count epoch on every call.
`Cache::load()` maintains a thread-local copy refreshed lazily when a write occurs.
For a PDP where every request reads policy, the Cache wrapper provides 10-25x
speedup on the hot path. The current design omits it.

### Reload triggers

Two mechanisms are sufficient:
1. **File watcher** (`notify` crate): Watch policy directory, reload on change
2. **HTTP admin endpoint**: `POST /admin/reload` for manual/automated triggers

SIGHUP and periodic polling add complexity without value. File watcher covers
automated reload; admin endpoint covers manual/CI-triggered reload.

The admin endpoint must be authenticated and rate-limited (see prerequisites.md).
Authentication is implemented via `PDP_ADMIN_TOKEN` Bearer token. Rate-limiting
is backlog.

### Policy delivery for multi-instance

For sidecar deployment, policy files are delivered to each pod independently (git
pull, S3 sync, webhook). Multi-instance coordination is deferred until remote
deployment (see ADR-003). When multiple instances exist, an epoch-based versioning
scheme is required (see prerequisites.md, P0-4).

## Consequences

- PolicyStore uses `ArcSwap<Arc<(PolicySet, Schema)>>` with Cache wrapper
- Two reload triggers only: file watcher + authenticated admin endpoint
- Policy CI/CD pipeline must be defined (git repo -> validation -> staging ->
  production) before production deployment
