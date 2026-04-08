# Entitlement Translation: Legacy IAM to Cedar

Compiled from `knowledge/raw/2026-04-08-entitlement-translation.md` on 2026-04-08.

## Overview

Patterns for mapping existing customer entitlements (database/LDAP/custom RBAC) into
Cedar's entity/policy model. Covers entity hierarchy design, RBAC/ABAC policy patterns,
JWT-to-entity mapping, entitlement sync strategies, policy templates for per-customer
permissions, and migration methodology.

## Cedar Entity Model

Every entity has three components:

- **Type** -- namespace-qualified name (e.g., `User`, `Role`, `SubscriptionTier`)
- **ID** -- string that with type uniquely identifies the entity
- **Attributes** -- key-value pairs (string, long, boolean, set, record, entity ref)

### Entity Hierarchy (DAG)

Entities form a directed acyclic graph through parent relationships. The `in` operator
tests membership transitively and reflexively.

```json
{
  "uid": { "type": "User", "id": "frank" },
  "parents": [
    { "type": "Role", "id": "admin" },
    { "type": "Team", "id": "engineering" }
  ],
  "attrs": { "email": "frank@example.com", "department": "engineering" }
}
```

`User::"frank" in Role::"admin"` -> true
`User::"frank" in Group::"superusers"` -> true (if Role::"admin" in Group::"superusers")

### Legacy-to-Cedar Entity Mapping

| Legacy Concept | Cedar Entity Type | Relationship |
|----------------|-------------------|-------------|
| Users table | `User` entity | Attributes from columns |
| Roles table | `Role` entity | `User in Role` via parent |
| Permissions table | Cedar policies | One policy per pattern |
| Groups/teams | `Group`/`Team` entity | `User in Team in Org` |
| Resources | Resource entities | Attributes from metadata |
| ACL entries | Discretionary policies | `principal == X, resource == Y` |

## RBAC Patterns

Cedar's RBAC uses principal groups as roles. Permissions are policies scoped to the
group; assignment is entity hierarchy management.

```cedar
// All admins can perform task operations
permit (
  principal in Role::"admin",
  action in [Action::"task:update", Action::"task:retrieve"],
  resource in ResourceType::"task"
);
```

### Key Separation

- **What a role can do** = policies (never changes with assignments)
- **Who has the role** = entity hierarchy (never changes with permissions)

### Resource-Scoped Roles

Two approaches to avoid role explosion:

**Separate groups**: `principal in Role::"approver-uk"` + `resource in Region::"UK"`

**Attribute conditions** (preferred): Single role + `when` clause checking
`principal.complianceOfficerCountries` against `resource.country`

### Action Groups

Group related actions: `Action::"ownerActions"` containing read/write/delete.
Write one policy for the group instead of one per action.

## ABAC Patterns

ABAC adds `when`/`unless` conditions referencing entity attributes:

```cedar
permit (
  principal is User,
  action == Action::"read",
  resource is Document
) when {
  principal.department == resource.department
} unless {
  resource.classification == "top-secret"
};
```

### Common Entitlement Patterns

**Subscription Tiers**: Model as entity groups. `Account in SubscriptionTier::"pro"`.
Make enterprise a parent of professional for automatic inheritance.

**Feature Flags**: Features as resources. Gate with tier membership or per-account
`permit` policies for overrides.

**Rate Limits**: Cedar evaluates thresholds, stateful counters live outside (Redis/DB).
`when { context.current_period_calls < principal.max_api_calls_per_month }`

**Data Scopes**: Classification as resource attributes, clearance as principal attributes.
`when { resource.data_scope in principal.allowed_scopes }`

## JWT-to-Cedar Entity Mapping

### The Cedarling Pattern (Production-Tested)

From JWT claims, construct Cedar entities:

```
sub claim          -> Principal entity ID
roles claim        -> Parent Role entities (User memberOf Role)
profile claims     -> Entity attributes (matching schema names)
org/group claims   -> Parent Organization/Group entities
```

### Rust Implementation

```rust
fn jwt_to_cedar_entities(claims: &JwtClaims, schema: &Schema) -> Vec<Entity> {
    let principal_uid = EntityUid::from_type_name_and_id(
        "App::User".parse().unwrap(),
        claims.sub.clone().into(),
    );

    let role_parents: HashSet<EntityUid> = claims.roles.iter()
        .map(|r| EntityUid::from_type_name_and_id(
            "App::Role".parse().unwrap(), r.clone().into(),
        )).collect();

    let attrs = build_attrs_from_claims(claims, schema);
    let principal = Entity::new(principal_uid, attrs, role_parents);

    // Also emit the Role entities themselves
    let role_entities = claims.roles.iter()
        .map(|r| Entity::new(
            EntityUid::from_type_name_and_id("App::Role".parse().unwrap(), r.clone().into()),
            HashMap::new(), HashSet::new(),
        ));

    std::iter::once(principal).chain(role_entities).collect()
}
```

### Workload Identity (M2M)

Access tokens map to `Workload` entity: `aud`/`client_id` -> entity ID, scopes ->
`Set<String>` attribute queryable with `.contains()`.

## Entitlement Sync Patterns

| Pattern | Latency | Consistency |
|---------|---------|-------------|
| **Event-driven push** | Seconds | Near-real-time |
| **Batch pull** | Minutes-hours | Eventually consistent |
| **Request-time pull** | Zero (always fresh) | Strongly consistent |
| **Hybrid** | Seconds + periodic cleanup | Near-real-time + guarantees |

**Request-time construction** (simplest for starting): Build entities from DB at
request time. Always consistent, no sync infrastructure. Mitigate latency with
short-TTL cache (30-60s), invalidated on entitlement change events.

### Eventual Consistency Implications

- **Upgrade latency**: Customer may be denied new features briefly. Mitigate with
  optimistic client-side checks.
- **Downgrade latency**: Brief continued access. Usually acceptable.
- **Revocation latency**: Security-critical revocations need a real-time deny list
  checked in `context`.

## Policy Templates

Templates use `?principal`/`?resource` placeholders, instantiated by linking entities:

```cedar
// Template: tier-feature-grant
permit (
  principal in ?principal,
  action == Action::"access",
  resource in ?resource
);

// Instantiation: Account::"acme-corp" gets professional features
// Link: ?principal = Account::"acme-corp", ?resource = FeatureSet::"professional"
```

Template text changes propagate to ALL linked policies. Ideal for per-customer
variable permissions (feature grants, custom scopes, time-limited access).

### Templates vs Groups for RBAC

| Approach | Policy Changes on Assignment | Entity Store Changes |
|----------|------------------------------|---------------------|
| Groups | None | Add/remove parent |
| Templates | Create/archive linked policy | None |

Groups simpler for standard RBAC. Templates better when permission itself varies
per assignment.

## Migration Methodology

### Six-Phase Approach

1. **Behavioral Audit**: Document every authorization decision path. Build
   principal/action/resource/condition/outcome matrix.
2. **Entity Model Design**: Map existing data model to Cedar entities and schema.
3. **Policy Translation**: Convert each rule to Cedar. RBAC scope + ABAC conditions
   + forbid overrides.
4. **Shadow Mode / Dual-Run**: Run Cedar alongside legacy. Both evaluate, legacy
   enforces. Log and compare all decisions.
5. **Parity Verification**: Track agreement rate per endpoint. Target 100% before cutover.
   Snapshot entities at decision time for replay debugging.
6. **Incremental Cutover**: Switch endpoints one at a time. Legacy stays in reversed
   shadow mode as safety net.

### Key Principle

"Don't change your existing logic. Make the new logic match it." First achieve parity,
THEN iterate on the Cedar model. Conflating migration with improvement creates
undiagnosable failures. (Oso methodology)

### Decision Comparison Logging

```
Request -> [Legacy] -> legacy_decision
        -> [Cedar]  -> cedar_decision + determining_policies
        -> [Logger] -> log(request, both_decisions, policies, entity_snapshot)
```

Categorize mismatches: policy gap, over-permission, under-permission, data mismatch,
timing difference.

### Rollback

Runtime config flag (not deploy). `enforcement_mode` = "cedar" | "shadow" | "legacy".
Rollback is one config change.

### Formal Analysis

Cedar's SMT-based tools can verify:
- Safety properties ("no non-admin can delete resources")
- Liveness properties ("every resource is accessible by someone")
- **Migration equivalence** ("policy set A = policy set B for all inputs")

## Sources

- Cedar docs: docs.cedarpolicy.com
- Cedar RBAC best practices: docs.cedarpolicy.com/bestpractices/bp-implementing-roles.html
- Cedar policy templates: docs.cedarpolicy.com/policies/templates.html
- AWS Verified Permissions identity sources: docs.aws.amazon.com
- Cedarling project (Janssen): github.com/JanssenProject/jans
- Oso migration methodology: osohq.com/post/launching-oso-migrate
- Permit.io Cedar RBAC: permit.io/blog/cedar-rbac
