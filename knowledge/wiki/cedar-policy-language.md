# Cedar Policy Language

Compiled from `knowledge/raw/2026-04-08-cedar-policy-deep-dive.md` on 2026-04-08.

## Overview

Cedar is an open-source authorization policy language and engine by AWS (Apache 2.0,
first released 2023-05-10). Current version: 4.9.1. Formally verified via Lean proofs
and differential testing. Not Turing-complete by design -- guarantees termination and
bounded latency.

- Repository: github.com/cedar-policy/cedar
- Docs: docs.cedarpolicy.com
- Rust crate: `cedar-policy` on crates.io

## Core Concepts

### PARC Request Model

Every authorization request is a 4-tuple:

1. **Principal** -- the entity making the request (e.g., `User::"alice"`)
2. **Action** -- the operation attempted (e.g., `Action::"view"`)
3. **Resource** -- the target entity (e.g., `File::"93"`)
4. **Context** -- environmental data as a record (IP, time, MFA status)

### Policy Structure

```cedar
[@annotation("value")]
effect (
    principal [constraint],
    action [constraint],
    resource [constraint]
)
[when { condition }]
[unless { condition }];
```

- **Effect**: `permit` or `forbid` only
- **Scope**: principal, action, resource constraints (all three mandatory)
- **Conditions**: optional `when`/`unless` clauses (AND together)

### Decision Algorithm

1. If ANY `forbid` policy is satisfied -> **Deny** (forbid overrides permit)
2. Else if ANY `permit` policy is satisfied -> **Allow**
3. Else -> **Deny** (default deny)

Skip-on-error: policies that error during evaluation are skipped, not treated as
deny. This prevents a buggy policy from causing global lockout.

### Scope Constraints

```cedar
principal == User::"alice"           // exact match
principal in Group::"admins"         // hierarchy membership (transitive)
principal is User                    // entity type check
principal is User in Group::"admins" // type + hierarchy
action in [Action::"view", Action::"edit"]  // action set
resource in Album::"vacation"        // resource hierarchy
```

### Data Types

Primitives: `Bool`, `String`, `Long` (64-bit signed integer).
Collections: `Set<T>`, `Record` (named key-value).
Extension types: `ipaddr`, `decimal`, `datetime`, `duration` (via constructors).
Entity references: `Type::"id"` format.

### Operators

- Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
- Logical: `&&`, `||`, `!`
- Arithmetic: `+`, `-`, `*` (integer only, no division/modulo)
- Hierarchy: `in` (transitive membership), `is` (type check)
- Attribute: `.field`, `["key"]`, `has` (presence test)
- Set: `contains`, `containsAll`, `containsAny`
- String: `like` (glob with `*` wildcard only -- no regex)
- Conditional: `if ... then ... else ...`
- IP/Datetime: `ip()`, `.isInRange()`, `datetime()`, `duration()`

## Schema System

Cedar schemas define entity types, attributes, and valid action-entity relationships.
Two formats: human-readable Cedar syntax (recommended) and JSON.

```cedar
namespace MyApp {
    entity User in [Role, Team] {
        email: String,
        department: String,
        subscription_tier: String,
    };

    entity Role;

    action ViewDocument appliesTo {
        principal: [User],
        resource: Document,
        context: { network: ipaddr, mfa: Bool }
    };
}
```

- Optional attributes marked with `?`
- Enumerated entity types: `entity Role enum ["admin", "viewer", "editor"]`
- Common type aliases: `type AuthContext = { network: ipaddr, mfa: Bool };`
- `tags String` for dynamic key-value data on entities

## Rust Crate API (`cedar-policy` 4.x)

### Core Types

```rust
use cedar_policy::{
    Authorizer, PolicySet, Request, Entities, Context,
    Schema, Response, Decision, EntityUid, EntityTypeName,
    EntityId, Entity, RestrictedExpression,
};
```

### Evaluation Flow

```rust
let policies: PolicySet = cedar_source.parse().unwrap();
let authorizer = Authorizer::new();  // stateless, cheap, Clone
let request = Request::new(principal, action, resource, context, None).unwrap();
let response = authorizer.is_authorized(&request, &policies, &entities);

match response.decision() {
    Decision::Allow => { /* permitted */ }
    Decision::Deny => { /* denied */ }
}
// response.diagnostics().reason() -- determining policy IDs
// response.diagnostics().errors() -- evaluation errors
```

### Entity Construction

```rust
let uid = EntityUid::from_type_name_and_id(
    EntityTypeName::from_str("User").unwrap(),
    EntityId::from_str("alice").unwrap(),
);
let mut attrs = HashMap::new();
attrs.insert("dept".to_owned(), RestrictedExpression::new_string("eng".to_owned()));
let parents = HashSet::from([role_uid]);
let entity = Entity::new(uid, attrs, parents).unwrap();
let entities = Entities::from_entities([entity], Some(&schema)).unwrap();
```

### Policy Templates

Templates use `?principal` and/or `?resource` placeholders, instantiated by linking
concrete entities. Template text changes propagate to all linked policies.

```rust
policy_set.add_template(template)?;
policy_set.link(template_id, new_id, HashMap::from([(SlotId::principal(), uid)]))?;
```

### Feature Flags

- `partial-eval`: Enables `is_authorized_partial()` for unknown values (experimental)
- `tpe`: Type-aware partial evaluation for access enumeration (experimental)

## Performance

- **Sub-millisecond evaluation** for typical policy sets (hundreds of policies)
- **28-35x faster than OpenFGA**, **42-81x faster than OPA/Rego** (Teleport benchmarks)
- Complexity: O(n) common case, O(n^2) worst case (set containment)
- Built-in policy slicing: only evaluates policies whose scope matches the request types
- No loops, no recursion, no external data fetch -- bounded evaluation guaranteed

## Deliberate Limitations

1. No loops or recursion (termination guarantee)
2. No external data fetching (all data must be provided upfront)
3. Boolean-only decisions (Allow/Deny, no structured responses)
4. No custom functions (not Turing-complete)
5. Rudimentary string matching (`like` with `*` only, no regex)
6. No integer division/modulo
7. Smaller ecosystem than OPA (fewer integrations, less operational tooling)
8. No built-in policy management APIs (library only, build your own)
9. Validator is conservative -- may reject some valid expressions

## Cedar vs OPA/Rego

| Dimension | Cedar | OPA/Rego |
|-----------|-------|----------|
| Language | DSL (authorization only) | General-purpose policy |
| Decision | Boolean (Allow/Deny) | Arbitrary JSON |
| Deployment | Library (embed) | Sidecar/daemon + HTTP API |
| Performance | Sub-ms, 42-81x faster | Slower, requires sidecar |
| Verification | Lean proofs + SMT | None |
| Schema | Built-in, sound validator | Optional |
| Ecosystem | Smaller, growing | Large, mature |

Cedar is the stronger choice for API gateway PDP: PARC maps to HTTP requests,
sub-ms latency, Rust-native (no IPC), default-deny matches API security.

## Sources

- cedar-policy crate docs: docs.rs/cedar-policy
- Cedar Language Reference: docs.cedarpolicy.com
- Cedar academic paper: arxiv.org/pdf/2403.04651
- Teleport benchmarks: goteleport.com/blog/benchmarking-policy-languages/
- StrongDM guide: strongdm.com/cedar-policy-language
