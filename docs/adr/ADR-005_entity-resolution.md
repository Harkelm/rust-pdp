# ADR-005: Entity Resolution Strategy

**Status**: Accepted  
**Date**: 2026-04-08  
**Source**: Architecture roundtable RT-26

## Context

Cedar is deliberately stateless -- the caller must supply all relevant entity data
with each authorization request. Three resolution approaches exist: JWT-only
(stateless), DB lookup per request (always fresh), cached entity hierarchy
(arc-swap + TTL refresh).

## Decision

**Tiered resolution by attribute security class.**

Entity attributes are classified into three tiers with different resolution
mechanisms:

### Tier 1: Non-revocable identity (from JWT claims)

Attributes that cannot be revoked with immediate effect and are bound to the
authentication token:
- `sub` claim -> principal entity ID
- `email`, `department`, `org` -> entity attributes
- Token-scoped metadata

These may come from PEP-supplied JWT claims because staleness does not create a
security window. JWT signature validation (performed by Kong's JWT plugin at
priority 1450, before the authz plugin) authenticates these claims.

### Tier 2: Revocable entitlements (from PDP-owned DB)

Attributes that can be revoked and where stale data creates a security window:
- Role memberships
- Permission grants
- Subscription tier
- Feature flags

These MUST be resolved by the PDP from its own authoritative data store. They
must NOT come from JWT claims, even if the JWT contains role claims. JWT role
claims may serve as hints for lookup optimization but are never authoritative.

Rationale: JWT signature validity is authentication freshness, not authorization
freshness. A token issued before a role revocation is a valid-signature token with
wrong entitlements. The revocation window equals the token lifetime, which may be
minutes to hours.

### Tier 3: Static hierarchy (arc-swap with event-driven refresh)

Organizational structure, group memberships, action groups -- data that changes
infrequently and applies across all principals:
- `Role::"admin" in Group::"superusers"`
- `Action::"ownerActions"` containing read/write/delete
- Org hierarchy

Loaded on startup, cached in `ArcSwap<Entities>`, refreshed on change events.

### Revocation fast-path

For emergency revocations (terminated employee, compromised agent), a deny list
checked before Cedar evaluation provides bounded revocation latency independent of
cache TTL. The deny list is a small, hot table checked in O(1). Without it, the
security boundary for revocation is the entity cache TTL (30-60s).

### Machine identity (agents/workloads)

Agent principals are classified by lifetime:
- **Short-lived workers** (lifetime < 60s): JWT TTL matches agent lifetime. No
  revocation infrastructure needed -- token expires with the agent.
- **Long-running agents**: Hybrid with deny list. Lamport's 30-60s revocation
  window concern applies directly.
- **Persistent service identities**: Full entity lifecycle, DB-backed resolution.

## Decision cache

Skip the decision cache at MVP. Cedar evaluates in 0.1-1ms -- the smallest
component of total request latency. The decision cache introduces stale-allow
risk, cache stampede on TTL expiry, and an unversioned cache key that does not
track policy or entity epoch. Add decision caching only when profiling shows Cedar
evaluation is the actual bottleneck. Keep the entity cache (Tier 3 arc-swap).

If decision caching is added later:
- Cache key must include policy epoch
- Jitter or stale-while-revalidate required to prevent stampede
- Invalidate entire cache on policy reload

## Consequences

- PDP API must enforce the tier classification -- not accept arbitrary entities
  from callers
- If thin Lua plugin (ADR-001 Path A) is chosen, entity trust boundary is
  structural (plugin cannot supply entities)
- If Go plugin (ADR-001 Path B) is chosen, PDP API must partition trusted vs
  untrusted entity input channels
- Forbid policy conditions must only reference required (non-optional) schema
  attributes to prevent skip-on-error bypass (see prerequisites.md, P0-2)
