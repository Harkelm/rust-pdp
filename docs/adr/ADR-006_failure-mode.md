# ADR-006: Failure Mode (Fail-Open vs Fail-Closed)

**Status**: Accepted  
**Date**: 2026-04-08  
**Source**: Architecture roundtable RT-26 (9/9 unanimous on FailOpen removal)

## Context

The proposed architecture had `FailOpen bool` as a per-route configuration field
in the Kong plugin Config struct. Every panelist (9/9) independently flagged this
as a P0 security issue. The field allows silent authorization bypass with no audit
trail, no alerting, no time bound.

## Decision

**Fail-closed with differentiated response codes. No runtime fail-open toggle.**

### Response code contract

The Kong plugin must distinguish three PDP response states:

| PDP State | Plugin Response | Client Semantics |
|-----------|----------------|-----------------|
| PDP returns `decision: Deny` | **403 Forbidden** | Authorization denied by policy. Do not retry. |
| PDP returns HTTP 503 | **503 + Retry-After** | PDP overloaded. Retry with backoff. |
| PDP timeout (no response) | **503 + Retry-After** | PDP unavailable. Unknown state is not a denial, it's an outage. |
| PDP returns `decision: Allow` | Pass through | Authorized. |

Critical: a PDP timeout must never produce 403. Returning 403 for a timeout masks
an availability problem as a security decision. Operations thinks it's a security
incident; security thinks it's an ops incident; nobody fixes the overload.

### Emergency override (human-ceremony only)

If fail-open is ever legitimately needed (extended PDP outage during a critical
business window), it requires:

1. **Mandatory audit log entry** on activation: who, when, which routes, incident
   reference
2. **Security team alert** on activation (not ops team -- security)
3. **Automatic time-bound expiry** (configurable, e.g., 4 hours) with reversion to
   fail-closed without operator action
4. **Per-route scope only** -- global fail-open is equivalent to disabling
   authorization

This is a deployment change with ceremony, not a config boolean.

### Non-blocking routes

If specific routes should not block on authorization failure, model that in Cedar
policy (e.g., a permit policy for health check endpoints), not in the plugin
config. This makes authorization intent visible and auditable.

## Consequences

- `FailOpen bool` removed from plugin Config struct
- Plugin must parse PDP HTTP status codes, not just response body
- PDP must return 503 when overloaded (admission control / backpressure), not
  silently queue until OOM
- Agent callers can handle 503+Retry-After with exponential backoff automatically
- Decision audit logging (see prerequisites.md) is required to detect when
  fail-open was active during a security incident
