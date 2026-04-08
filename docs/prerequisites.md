# Architecture Prerequisites

These are P0 findings from the architecture roundtable (RT-26) that must be
resolved before implementation work begins. Downstream tasks (scaffold, plugin,
schema design, integration test, etc.) depend on these decisions.

## P0-1: Remove FailOpen config toggle

**Decision**: See ADR-006.  
**Implementation**: Remove `FailOpen bool` from plugin Config struct. Implement
503+Retry-After for PDP unavailability. Emergency override requires deployment
change with audit+alert+time-bound ceremony.

## P0-2: Mandatory pre-evaluation schema validation

**Problem**: Cedar's skip-on-error semantics mean policies that error during
evaluation are skipped, not denied. A missing entity attribute on a `forbid`
policy causes it to skip, allowing `permit` policies to fire. An attacker who
controls entity data can selectively neuter forbid rules.

**Mitigation**: Validate all entity attributes against the Cedar schema before
calling `is_authorized()`. Validation failure = deny (not pass-through to
evaluation). This is the PDP's responsibility, not Cedar's -- Cedar's behavior
is by design.

**Policy authoring rule**: All entity attributes referenced in `forbid` policy
conditions must be marked as required (not `?`) in the Cedar schema. Optional
attributes in forbid conditions re-enable the skip-on-error bypass. This must be
a documented and enforced convention.

## P0-3: PEP/PDP entity trust contract

**Problem**: The PDP API accepts an `entities` array unconditionally. The
architecture warns "PDP should NOT trust PEP-supplied entity data for
security-critical attributes" but this is prose, not enforcement.

**Mitigation**: See ADR-005 entity tiering. If thin Lua plugin (ADR-001 Path A)
is chosen, this is resolved structurally -- the plugin sends only principal ID +
request context. If Go plugin (Path B) is chosen, the PDP API must partition
entity input into trusted (PDP-resolved) and untrusted (PEP-supplied hints) with
enforcement at the API level.

Additionally: the AuthZen endpoint's `subject.properties` field is a freeform
JSON bag with no schema constraint. The mapping layer from AuthZen to Cedar
entities must be a validation boundary, not just a translation layer.

## P0-4: Multi-instance policy consistency model

**Problem**: Multiple PDP instances (sidecar or remote) can hold different active
policy sets during rolling reload. Two concurrent requests can receive
contradictory decisions.

**Mitigation**: Not required for initial sidecar deployment (single instance per
pod). Must be specified before remote deployment or multi-pod scaling:
- Option A: Epoch-based versioning -- decisions carry the policy epoch, stale
  decisions are identifiable
- Option B: Activation barrier -- global coordination ensures all instances swap
  simultaneously
- Option C: Explicit eventual consistency with a stated maximum staleness bound

For MVP sidecar deployment, document that single-instance-per-pod is a constraint
and multi-instance requires this prerequisite.

## Backlog Items Needed

The following should be added to the backlog to track resolution of these
prerequisites. They should block the implementation tasks that depend on them:

- **Latency SLA definition** -- required before ADR-001 plugin language decision
  can be finalized. Blocks scaffold tasks.
- **Policy CI/CD pipeline spec** -- git repo -> validation -> staging -> production.
  Blocks production deployment.
- **Decision audit logging architecture** -- persist Cedar diagnostics for
  compliance and post-incident analysis. Blocks production deployment.
- **Admin endpoint authentication** -- POST /admin/reload must be authenticated
  and rate-limited. **Status: Addressed.** `PDP_ADMIN_TOKEN` env var enables
  Bearer token authentication. Rate-limiting not yet implemented (backlog).
