---
source: web-research
date: 2026-04-08
project: rust-pdp
tags: [entitlements, iam, cedar, migration, rbac, abac]
---

# Translating Customer Entitlements to Cedar IAM Model

Research on mapping existing customer entitlements (database/LDAP/custom) into
Cedar's entity/policy model for evaluation by a Rust PDP.

---

## 1. Cedar Entity Model and Hierarchies

Cedar's authorization model is built on **entities** -- stored objects that serve
as principals, actions, and resources. Every entity has three components:

- **Entity type** -- a namespace-qualified type name (e.g., `User`, `Role`, `Subscription`)
- **Entity ID (EID)** -- a string that, combined with the type, uniquely identifies the entity
- **Attributes** -- key-value pairs of any Cedar-supported type (string, long, boolean, set, record, entity reference)

### Entity Hierarchy (DAG)

Entities form a **directed acyclic graph (DAG)** through parent relationships. A
`User` entity can be a member of a `Role` entity, which can itself be a member of
a higher-level `Role` or `Group`. The JSON representation:

```json
{
  "uid": { "type": "User", "id": "frank" },
  "parents": [
    { "type": "Role", "id": "admin" },
    { "type": "Team", "id": "engineering" }
  ],
  "attrs": {
    "email": "frank@example.com",
    "department": "engineering"
  }
}
```

The `in` operator tests membership transitively: if `User::"frank"` is in
`Role::"admin"` and `Role::"admin"` is in `Group::"superusers"`, then
`User::"frank" in Group::"superusers"` evaluates to `true`. The `in` operator
is also reflexive -- an entity is always `in` itself.

### Schema Declaration

Cedar schemas define entity types, their allowed parent types, and attribute
shapes. Schemas use a Cedar-native format (recommended) or JSON:

```cedar
entity Role;

entity User in [Role, Team] = {
  email: String,
  department: String,
  subscription_tier: String,
};

entity Document = {
  owner: User,
  classification: String,
  department: String,
};
```

### Implication for Entitlement Translation

Your existing user-role-permission model maps directly to Cedar's entity
hierarchy. Database rows like `user_roles(user_id, role_id)` become parent
relationships on the `User` entity. The hierarchy replaces JOIN-based permission
lookups with graph membership tests.

---

## 2. RBAC Patterns in Cedar

Cedar's recommended RBAC pattern uses **principal groups to represent roles**.
Permissions are expressed as policies scoped to the group, and role assignment
is managed by adding/removing entities from groups.

### Basic RBAC Policy

```cedar
// All admins can perform any action on any task
permit (
  principal in Role::"admin",
  action in [Action::"task:update", Action::"task:retrieve", Action::"task:list"],
  resource in ResourceType::"task"
);
```

### Multi-Role Assignment

A single user can be a member of multiple roles simultaneously. The authorization
engine evaluates all applicable policies and permits the request if any `permit`
policy matches (and no `forbid` policy overrides it).

### Resource-Scoped Roles

For roles that apply only to specific resource groups (e.g., "approver for UK
timesheets"), Cedar supports two approaches:

**Approach A -- Separate groups per scope:**

```cedar
permit (
  principal in Role::"approver-uk",
  action in Action::"ApproverActions",
  resource in TimesheetGrp::"UK"
);
```

**Approach B -- Attribute conditions on a single role:**

```cedar
permit (
  principal in Role::"ComplianceOfficer",
  action == Action::"approveAudit",
  resource is Audit
) when {
  principal has complianceOfficerCountries &&
  resource.country in principal.complianceOfficerCountries
};
```

Approach B avoids role explosion by encoding scope as principal attributes.

### Action Groups

Actions can themselves form hierarchies. Define an `Action::"ownerActions"` group
containing `Action::"read"`, `Action::"write"`, `Action::"delete"`, then write
one policy for the group rather than one per action.

### Key Separation: Policies vs. Assignments

Cedar separates **what a role can do** (policies) from **who has the role**
(entity hierarchy). Changing role assignments never requires policy changes.
Changing what a role can do never requires touching the identity store.

---

## 3. ABAC (Attribute-Based Access Control) in Cedar

ABAC policies add `when` and `unless` condition clauses that reference entity
attributes. The policy scope handles RBAC; conditions handle ABAC. They combine
naturally:

### Condition Syntax

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

- `when` -- the policy applies only if the condition is true
- `unless` -- the policy does NOT apply if the condition is true (acts as an exception)
- Multiple `when`/`unless` clauses can be chained (they AND together)

### Available Operators

| Category | Operators |
|----------|-----------|
| Comparison | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| Logical | `&&`, `\|\|`, `!` |
| String | `like` (with `*` wildcard) |
| Set | `.contains()`, `.containsAll()`, `.containsAny()`, `.isEmpty()` |
| Attribute presence | `has` (e.g., `principal has email`) |
| Hierarchy | `in`, `is` |
| Conditional | `if ... then ... else ...` |
| IP address | `ip()`, `.isInRange()`, `.isLoopback()`, `.isMulticast()` |
| Temporal | `datetime()`, `duration()`, comparison operators on both |
| Decimal | `decimal()`, `.lessThan()`, `.greaterThan()`, etc. |
| Tags | `.hasTag()`, `.getTag()` |

### Context Object

The `context` record carries per-request data not stored on entities -- IP
address, request time, MFA status, client type:

```cedar
permit (
  principal in Role::"analyst",
  action == Action::"read",
  resource
) when {
  context.current_time >= context.business_hours_start &&
  context.current_time <= context.business_hours_end &&
  context.mfa_verified == true
};
```

### Nested Attribute Access

Cedar supports dotted paths for nested records:

```cedar
when {
  principal has contactInfo.address.zip &&
  principal.contactInfo.address.zip == "90210"
}
```

---

## 4. Common Entitlement Patterns Mapped to Cedar

### Subscription Tiers

Model tiers as entity groups. Each customer's `Account` entity is a member of a
`SubscriptionTier` entity:

```json
{
  "uid": { "type": "Account", "id": "acme-corp" },
  "parents": [{ "type": "SubscriptionTier", "id": "professional" }],
  "attrs": {
    "max_seats": 50,
    "max_api_calls_per_month": 100000
  }
}
```

```cedar
// Professional tier can access analytics
permit (
  principal in SubscriptionTier::"professional",
  action == Action::"access",
  resource in Feature::"analytics"
);

// Enterprise tier gets everything professional gets, plus audit logs
permit (
  principal in SubscriptionTier::"enterprise",
  action == Action::"access",
  resource in Feature::"audit-logs"
);
```

Make `SubscriptionTier::"enterprise"` a parent of `SubscriptionTier::"professional"`
to inherit all professional permissions automatically.

### Feature Flags

Model features as resources. Gate access with policies that check tier membership
or explicit per-account overrides:

```cedar
// Beta feature: only accounts with beta_access flag
permit (
  principal is Account,
  action == Action::"access",
  resource == Feature::"new-dashboard"
) when {
  principal has beta_access && principal.beta_access == true
};
```

For per-customer overrides (e.g., sales granting a feature to a specific account),
use discretionary policies:

```cedar
permit (
  principal == Account::"acme-corp",
  action == Action::"access",
  resource == Feature::"advanced-reporting"
);
```

### Rate Limits

Cedar itself does not track stateful counters, but it can express rate limit
*tiers* as attributes and let the PDP middleware enforce them:

```cedar
// Context carries current usage from your rate-limit store
permit (
  principal is Account,
  action == Action::"api-call",
  resource
) when {
  context.current_period_calls < principal.max_api_calls_per_month
};
```

The pattern: your rate-limit middleware populates `context` with current usage,
Cedar evaluates whether the request is within bounds. The counter state lives
outside Cedar (Redis, database); Cedar just evaluates the threshold.

### Data Access Scopes

Model data classification as resource attributes and required clearance as
principal attributes:

```cedar
permit (
  principal is User,
  action == Action::"read",
  resource is DataRecord
) when {
  resource.data_scope in principal.allowed_scopes
};
```

Or use `forbid` policies to restrict access to sensitive data:

```cedar
forbid (
  principal is User,
  action,
  resource is DataRecord
) when {
  resource.classification == "pii"
} unless {
  principal has pii_access && principal.pii_access == true
};
```

---

## 5. Migration Patterns: Legacy ACL/RBAC to Cedar

### Phase 1: Behavioral Audit

Document every authorization decision path in your current system. Build a
comprehensive matrix of: principal types, actions, resource types, conditions,
and expected outcomes. This phase frequently uncovers undocumented edge cases
and implicit assumptions.

### Phase 2: Entity Model Design

Map your existing data model to Cedar entities:

| Legacy Concept | Cedar Entity Type | Relationship |
|----------------|-------------------|-------------|
| Users table | `User` entity | Attributes from user columns |
| Roles table | `Role` entity | `User in Role` via parent |
| Permissions table | Cedar policies | One policy per permission pattern |
| Groups/teams | `Group`/`Team` entity | `User in Team`, `Team in Org` |
| Resources | Resource entities | Attributes from resource metadata |
| ACL entries | Discretionary policies | `principal == X, resource == Y` |

### Phase 3: Policy Translation

Translate each authorization rule into Cedar policies. Common patterns:

- **Row-level ACL** (`user_id = 5 can access resource_id = 10`) becomes a
  discretionary policy or template-linked policy
- **Role-permission mapping** (`role=admin grants action=delete`) becomes an
  RBAC policy with `principal in Role::"admin"`
- **Conditional rules** (`if user.department = resource.department`) becomes
  a `when` clause with attribute comparison

### Phase 4: Shadow Mode / Dual-Run

Run Cedar alongside your existing system without controlling access:

1. On each authorization request, call both the legacy system and Cedar
2. Log both decisions with the full request context
3. Compare decisions -- capture and categorize discrepancies
4. The legacy system continues enforcing; Cedar runs in observation mode

Categories of discrepancies to watch for:
- **Logic differences** -- the Cedar policy doesn't match the legacy rule
- **Data differences** -- entity attributes are stale or missing
- **Timing differences** -- rate limits or time-based rules diverge
- **Format differences** -- legacy returns partial/conditional access that doesn't
  map cleanly to allow/deny

### Phase 5: Parity Verification

Track decision agreement rate over time. Target 100% agreement on a per-endpoint
basis before cutover. Use **data snapshotting** to capture point-in-time state of
all entities used in a decision, enabling replay of prior mismatches even as
authorization data changes.

### Phase 6: Incremental Cutover

Switch endpoints one at a time from legacy to Cedar enforcement, keeping the
legacy system in shadow mode (reversed) as a safety net. Roll back individual
endpoints if discrepancies appear.

### Key Principle

The Oso migration methodology emphasizes: "Don't change your existing logic. Make
the new logic match it." First achieve parity, then iterate on the Cedar model to
improve it. Conflating migration with improvement creates undiagnosable failures.

---

## 6. AWS Verified Permissions Identity Source Integration

AWS Verified Permissions (AVP) provides a managed Cedar service with native
identity source integration. Even if you self-host the Rust PDP, AVP's patterns
are instructive.

### Identity Source Types

1. **Amazon Cognito user pools** -- AVP auto-discovers pool configuration,
   validates tokens, maps claims to entities
2. **OIDC providers** -- any compliant IdP (Okta, Auth0, Keycloak, etc.) via
   issuer URL and `/.well-known/openid-configuration`

### Token-to-Entity Mapping

| Token Type | Mapping Target | Use Case |
|-----------|---------------|----------|
| ID token | Principal attributes | User profile data (email, name, department) |
| Access token | Context attributes | Scopes, permissions, client metadata |
| Group claims | Principal group membership | RBAC via `principal in Role::X` |

For ID tokens, AVP maps attribute claims directly to principal entity attributes.
The schema must declare which attributes the principal type has, and the claim
names must match. For access tokens, claims go into the `context` record rather
than principal attributes.

### Group Claim Mapping

The `groups` claim (or equivalent) from the token is mapped to Cedar group
membership. If a JWT contains `"groups": ["admin", "engineering"]`, AVP creates
parent relationships: `User::"sub-value" in Role::"admin"` and `User::"sub-value"
in Role::"engineering"`.

### Schema Requirements

Your Cedar schema must declare the principal entity type matching what the
identity source creates, including all attributes you reference in policies.
Attributes not in the schema are silently ignored.

### Self-Hosted Applicability

For a self-hosted Rust PDP, replicate this pattern:

1. Validate the JWT (signature, expiration, issuer, audience)
2. Extract `sub` as the principal entity ID
3. Extract group claims as parent relationships
4. Extract profile claims as entity attributes
5. Build the Cedar `Entity` objects and pass them to the authorizer

---

## 7. JWT Claims to Cedar Entity Mapping

### The Cedarling Pattern (Janssen Project)

The Cedarling project (Janssen/Gluu) provides a production-tested pattern for
JWT-to-Cedar mapping in Rust:

**Principal construction:**
- Entity type: configured (e.g., `App::User`)
- Entity ID: from `sub` claim (fallback chain: `sub` from userinfo, then id_token)
- Attributes: JWT claims matching schema attribute names (1:1 default mapping)
- Parents: `role` claim values become `Role` entities as parents

**Example mapping:**

JWT claims:
```json
{
  "sub": "user_123",
  "email": "bob@example.com",
  "role": ["admin", "analyst"],
  "department": "engineering"
}
```

Cedar entities produced:
```json
[
  {
    "uid": { "type": "App::User", "id": "user_123" },
    "attrs": {
      "email": "bob@example.com",
      "department": "engineering"
    },
    "parents": [
      { "type": "App::Role", "id": "admin" },
      { "type": "App::Role", "id": "analyst" }
    ]
  },
  { "uid": { "type": "App::Role", "id": "admin" }, "attrs": {}, "parents": [] },
  { "uid": { "type": "App::Role", "id": "analyst" }, "attrs": {}, "parents": [] }
]
```

**Custom claim mapping:**
Cedarling supports a Token Entity Metadata Schema (TEMS) with a `claim_mapping`
field that allows remapping claim names to different attribute names, handling
type coercion, and ignoring unknown claims gracefully.

### Workload Identity (Machine-to-Machine)

For service-to-service auth, the `access_token` maps to a `Workload` entity:
- Entity ID: from `aud` or `client_id` claim
- Attributes: extracted from access token claims
- Scopes: mapped to a `Set<String>` attribute, queryable with `.contains()`

### Rust Implementation Pattern

```rust
fn jwt_to_cedar_entities(claims: &JwtClaims, schema: &Schema) -> Vec<Entity> {
    let principal_uid = EntityUid::from_type_name_and_id(
        "App::User".parse().unwrap(),
        claims.sub.clone().into(),
    );

    // Build role parent entities
    let role_parents: HashSet<EntityUid> = claims.roles.iter()
        .map(|r| EntityUid::from_type_name_and_id(
            "App::Role".parse().unwrap(),
            r.clone().into(),
        ))
        .collect();

    // Map claims to attributes (only those in schema)
    let attrs = build_attrs_from_claims(claims, schema);

    let principal = Entity::new(principal_uid, attrs, role_parents);

    // Also emit the Role entities themselves
    let role_entities = claims.roles.iter()
        .map(|r| Entity::new(
            EntityUid::from_type_name_and_id("App::Role".parse().unwrap(), r.clone().into()),
            HashMap::new(),
            HashSet::new(),
        ));

    std::iter::once(principal).chain(role_entities).collect()
}
```

---

## 8. Entitlement Sync Patterns

### Push vs. Pull

| Pattern | Mechanism | Latency | Consistency |
|---------|-----------|---------|-------------|
| **Event-driven push** | Webhook/event on entitlement change triggers entity store update | Seconds | Near-real-time |
| **Batch pull** | Periodic sync (cron) pulls full entitlement state | Minutes to hours | Eventually consistent |
| **Request-time pull** | Build entities from DB on each authorization request | Zero (always fresh) | Strongly consistent |
| **Hybrid** | Event-driven for hot path, batch for reconciliation | Seconds + periodic cleanup | Near-real-time with consistency guarantees |

### Event-Driven Push (Recommended for Most Cases)

When an entitlement changes (subscription upgrade, role assignment, feature flag
toggle), emit an event that updates the Cedar entity store:

1. Billing system fires `subscription.updated` webhook
2. Entitlement service translates the change to entity operations:
   - Add/remove parent relationships (tier changes)
   - Update attributes (new limits, new flags)
3. Entity store is updated atomically
4. Next authorization request sees the new state

### Request-Time Entity Construction

For a self-hosted Rust PDP, the simplest pattern avoids a separate entity store
entirely: build Cedar entities from your database at request time.

```
Request arrives -> Extract JWT -> Query DB for entitlements -> Build entities -> Authorize
```

Pros: always consistent, no sync infrastructure
Cons: adds DB query latency to every authorization call

Mitigation: cache entities with a short TTL (30-60 seconds), invalidate on known
entitlement change events.

### Batch Reconciliation

Even with event-driven sync, run periodic batch reconciliation:

1. Full-scan your entitlement database
2. Compare each entity in the Cedar store against source-of-truth
3. Fix any drift (missed events, failed updates)
4. Log discrepancies for operational alerting

### Eventual Consistency Implications

With any async sync pattern, there is a window where the Cedar entity store
lags behind the source of truth. Implications:

- **Upgrade latency**: a customer who just upgraded may be denied new features
  for seconds/minutes. Mitigate with optimistic client-side checks or
  request-time fallback for tier queries.
- **Downgrade latency**: a customer who just downgraded retains access briefly.
  Usually acceptable; if not, use `forbid` policies with real-time checks.
- **Revocation latency**: a user whose access is revoked retains it until sync
  completes. For security-critical revocations, use a real-time deny list
  checked in `context` alongside the entity store.

---

## 9. Cedar Policy Templates

### Core Concept

A policy template is a policy with **placeholders** (`?principal` and/or
`?resource`) that are instantiated later to create **template-linked policies**.
Templates define the permission pattern once; linked policies bind specific
entities to the pattern.

### Syntax

```cedar
// Template: shareable document access
permit (
  principal == ?principal,
  action in [Action::"view", Action::"comment"],
  resource == ?resource
) unless {
  resource.status == "archived"
};
```

Placeholders can appear only in the policy scope, on the right side of `==` or
`in`. Conditions (`when`/`unless`) cannot contain placeholders.

### Instantiation

Each template-linked policy binds concrete entities to the placeholders:

```
Template: "document-share"
  Link 1: ?principal = User::"alice",  ?resource = Document::"quarterly-report"
  Link 2: ?principal = User::"bob",    ?resource = Document::"quarterly-report"
  Link 3: ?principal = Team::"finance", ?resource = Document::"budget-2026"
```

### Per-Customer Policy Generation

Templates are ideal for entitlement patterns that vary per customer:

**Subscription-gated feature access:**

```cedar
// Template: tier-feature-grant
permit (
  principal in ?principal,
  action == Action::"access",
  resource in ?resource
);
```

When onboarding a customer to the "professional" tier:
```
Link: ?principal = Account::"acme-corp", ?resource = FeatureSet::"professional"
```

When they upgrade to enterprise:
```
Archive old link, create new:
Link: ?principal = Account::"acme-corp", ?resource = FeatureSet::"enterprise"
```

**Custom API access grants:**

```cedar
// Template: api-scope-grant
permit (
  principal == ?principal,
  action in Action::"ApiRead",
  resource in ?resource
) when {
  context.api_version in resource.supported_versions
};
```

### Dynamic Behavior

Template-linked policies are dynamic: if you update the template text, all linked
policies immediately reflect the change. This means you can fix a permission bug
or add a condition across all customers by editing one template.

### Lifecycle Management

Templates create operational obligations:
- **Onboarding**: create template-linked policies for the new customer's tier
- **Tier change**: archive old links, create new links
- **Offboarding**: archive all links for the departing customer
- **Audit**: linked policies maintain a clear audit trail back to the template

### Templates vs. Groups for RBAC

Two ways to implement roles:

| Approach | Mechanism | Policy Changes on Assignment | Entity Store Changes |
|----------|-----------|------------------------------|---------------------|
| Groups | `principal in Role::"X"` | None | Add/remove parent |
| Templates | `principal == ?principal` linked | Create/archive linked policy | None |

Groups are simpler for standard RBAC. Templates are better when the permission
itself varies per assignment (e.g., time-limited access, resource-scoped grants).

---

## 10. Audit and Rollback: Verifying Cedar Matches Legacy

### Cedar's Built-In Diagnostics

Every Cedar authorization response includes:

- **Decision**: `Allow` or `Deny`
- **Determining policies**: the specific policy IDs that caused the decision
- **Errors**: any policies that failed evaluation (type errors, missing attributes)

This data is the foundation of your audit trail.

### Decision Logging Architecture

```
Request -> [Legacy System] -> legacy_decision
        -> [Cedar PDP]     -> cedar_decision + determining_policies
        -> [Comparison Logger] -> log(request, legacy_decision, cedar_decision, policies)
```

Log every authorization decision with:
1. Full request context (principal, action, resource, context)
2. Entity snapshot (or entity version/hash)
3. Legacy decision
4. Cedar decision
5. Determining policy IDs
6. Timestamp

### Discrepancy Analysis

Categorize mismatches systematically:

| Category | Cause | Resolution |
|----------|-------|------------|
| **Policy gap** | Missing Cedar policy for a legacy rule | Write the missing policy |
| **Over-permission** | Cedar permits what legacy denies | Add `forbid` policy or tighten conditions |
| **Under-permission** | Cedar denies what legacy permits | Add `permit` policy or fix entity data |
| **Data mismatch** | Entity attributes don't match legacy data | Fix sync pipeline |
| **Timing** | Rate limits or temporal rules diverge | Align context data |

### Decision Replay

For debugging discrepancies after the fact:

1. **Snapshot entities at decision time** -- store the entity set used for each
   logged decision
2. **Replay** -- feed the same request + entity snapshot back through Cedar
3. **Trace** -- examine which policies matched and why

This is critical because entity data changes continuously. Without snapshots,
you cannot reliably reproduce a past decision.

### Automated Parity Testing

Build a continuous parity test suite:

1. Generate authorization requests from production traffic (anonymized if needed)
2. Run each request through both systems
3. Track agreement percentage per endpoint/action
4. Alert on regression (agreement drops below threshold)
5. Gate cutover on sustained 100% agreement per endpoint

### Rollback Strategy

Design for instant rollback at the enforcement point:

```rust
fn authorize(request: &AuthzRequest) -> Decision {
    let cedar_decision = cedar_pdp.evaluate(request);

    if config.enforcement_mode == "cedar" {
        log_decision(request, cedar_decision, None);
        cedar_decision
    } else if config.enforcement_mode == "shadow" {
        let legacy_decision = legacy_system.evaluate(request);
        log_comparison(request, legacy_decision, cedar_decision);
        legacy_decision  // Legacy still controls
    } else {
        legacy_system.evaluate(request)
    }
}
```

The enforcement mode is a runtime configuration flag (not a deploy). Rollback
is changing one config value, not redeploying code.

### Policy Versioning

Maintain policy versions in version control (Git). Each policy set has a version
identifier. The audit log records which policy version produced each decision.
Rollback to a previous policy version is a Git revert + policy store reload.

### Formal Analysis

Cedar supports automated reasoning tools (based on SMT solvers) that can verify
properties like:

- "No user outside the admin role can delete resources" (safety property)
- "Every resource is accessible by at least one principal" (liveness property)
- "Policy set A is equivalent to policy set B" (migration equivalence)

The equivalence check is directly applicable to migration: prove that your Cedar
policy set produces identical decisions to a formalized version of your legacy
rules for all possible inputs.

---

## Summary: Translation Checklist

1. **Inventory** existing entitlement types: roles, tiers, feature flags, scopes, rate limits
2. **Design entity types** in a Cedar schema for each principal, resource, and action type
3. **Map hierarchies**: user-role, account-tier, resource-group relationships become entity parents
4. **Translate rules to policies**: RBAC scope + ABAC conditions + forbid overrides
5. **Build templates** for per-customer variable permissions (feature grants, custom scopes)
6. **Implement JWT-to-entity mapping** in the Rust PDP (sub -> principal, roles -> parents, claims -> attrs)
7. **Choose sync pattern**: request-time for simplicity, event-driven for performance, batch for reconciliation
8. **Deploy in shadow mode**: dual-run with decision comparison logging
9. **Verify parity**: automated comparison, discrepancy categorization, replay testing
10. **Cut over incrementally**: endpoint by endpoint, with runtime rollback switch

---

## Sources

- [Cedar Policy Language Documentation](https://docs.cedarpolicy.com/)
- [Cedar Entities Reference](https://docs.cedarpolicy.com/policies/syntax-entity.html)
- [Cedar Design Patterns](https://docs.cedarpolicy.com/overview/patterns.html)
- [Cedar RBAC Best Practices](https://docs.cedarpolicy.com/bestpractices/bp-implementing-roles.html)
- [Cedar Roles with Policy Templates](https://docs.cedarpolicy.com/bestpractices/bp-implementing-roles-templates.html)
- [Cedar Policy Templates](https://docs.cedarpolicy.com/policies/templates.html)
- [Cedar Operators Reference](https://docs.cedarpolicy.com/policies/syntax-operators.html)
- [Cedar Authorization](https://docs.cedarpolicy.com/auth/authorization.html)
- [Cedar Schema Overview](https://docs.cedarpolicy.com/schema/schema.html)
- [Cedar Academic Paper (Amazon Science)](https://assets.amazon.science/96/a8/1b427993481cbdf0ef2c8ca6db85/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization.pdf)
- [AWS Verified Permissions Identity Sources](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/identity-sources.html)
- [AWS Verified Permissions Terminology](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/terminology.html)
- [AWS Prescriptive Guidance: Multi-tenant SaaS Authorization](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/cedar.html)
- [AWS: Migrating from OPA to Verified Permissions](https://aws.amazon.com/blogs/security/migrating-from-open-policy-agent-to-amazon-verified-permissions/)
- [AWS: How We Designed Cedar](https://aws.amazon.com/blogs/security/how-we-designed-cedar-to-be-intuitive-to-use-fast-and-safe/)
- [Permit.io: Implementing RBAC with Cedar](https://www.permit.io/blog/cedar-rbac)
- [Cedarling Project (Janssen) -- JWT to Cedar Entity Mapping](https://github.com/JanssenProject/jans/wiki/Cedarling-Project-Overview)
- [Cedarling Entity Mappings Reference](https://docs.jans.io/v1.15.0/cedarling/reference/cedarling-entities/)
- [Oso Migrate: Authorization Migration Methodology](https://www.osohq.com/post/launching-oso-migrate)
- [Auth0: Understanding ReBAC and ABAC Through OpenFGA and Cedar](https://auth0.com/blog/rebac-abac-openfga-cedar/)
- [Tutorial: Authorization with Cedar (Rust)](https://jun.codes/blog/authorization-with-cedar)
- [AWS Open Source Blog: Using Cedar for Custom Authorization](https://aws.amazon.com/blogs/opensource/using-open-source-cedar-to-write-and-enforce-custom-authorization-policies/)
- [StrongDM: Cedar Policy Language 2026 Guide](https://www.strongdm.com/cedar-policy-language)
- [Cedar: Avoiding the Cracks](https://onecloudplease.com/blog/cedar-avoiding-the-cracks)
- [Stigg: Entitlements Untangled](https://www.stigg.io/blog-posts/entitlements-untangled-the-modern-way-to-software-monetization)
- [LaunchDarkly: Entitlements with Feature Flags](https://launchdarkly.com/blog/how-to-manage-entitlements-with-feature-flags/)
- [Amazon Bedrock AgentCore: Cedar Entity Mapping](https://hidekazu-konishi.com/entry/amazon_bedrock_agentcore_implementation_guide_part2_security.html)
