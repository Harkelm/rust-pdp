---
source: web-research
date: 2026-04-08
project: rust-pdp
tags: [cedar, policy-language, authorization, rust]
---

# Cedar Policy Language Deep Dive

Research deposit for the rust-pdp project. All claims sourced from official docs,
the academic paper, crates.io, and community benchmarks. Source URLs inline.

---

## 1. What Is Cedar?

Cedar is an open-source policy language and authorization engine developed by
**Amazon Web Services**. It was first publicly announced and open-sourced on
2023-05-10 under the **Apache 2.0** license.

- **Current version**: 4.9.1 (released 2026-02-27, per crates.io)
  Source: https://crates.io/crates/cedar-policy
- **67 total releases** on crates.io as of research date
- **Repository**: https://github.com/cedar-policy/cedar
- **Documentation**: https://docs.cedarpolicy.com/
- **Playground**: https://www.cedarpolicy.com/

### Academic Foundation

Cedar has a peer-reviewed academic paper published in PACMPL (Proceedings of the
ACM on Programming Languages):

> "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization"
> https://dl.acm.org/doi/10.1145/3649835
> Also available: https://arxiv.org/pdf/2403.04651

The paper describes Cedar's formal semantics, verification-guided development
process, and the proofs of correctness for the validator and symbolic compiler.

### Rust Crate Ecosystem

The cedar-policy workspace contains these crates:

| Crate | Purpose | Public API? |
|-------|---------|-------------|
| `cedar-policy` | Main crate -- authorization, validation, policy parsing | Yes |
| `cedar-policy-cli` | Command-line tool for testing/evaluating policies | Yes |
| `cedar-policy-core` | Parser and evaluator internals | Internal |
| `cedar-policy-validator` | Schema-based policy validation | Internal |
| `cedar-policy-formatter` | Auto-formatter for Cedar syntax | Internal |
| `cedar-testing` | Integration test utilities | Internal |
| `cedar-wasm` | WebAssembly compilation target | Yes |
| `cedar-language-server` | LSP implementation for editor support | Yes |
| `cedar-policy-symcc` | Symbolic compiler (formal analysis) | Yes |

Source: https://github.com/cedar-policy/cedar

The public API surface is the `cedar-policy` crate. Internal crates (`-core`,
`-validator`, `-formatter`) are implementation details and not part of the
stability guarantee.

---

## 2. Cedar Policy Syntax

Source: https://docs.cedarpolicy.com/policies/syntax-policy.html

### Policy Structure

Every Cedar policy has this structure:

```
[@annotation("value")]
effect (
    principal [constraint],
    action [constraint],
    resource [constraint]
)
[when { condition }]
[unless { condition }];
```

- **Effect**: `permit` or `forbid` -- the only two options
- **Scope**: principal, action, resource -- all three are mandatory
- **Conditions**: zero or more `when`/`unless` clauses -- optional
- **Annotations**: key-value metadata with no effect on evaluation -- optional
- Policies always end with a semicolon

### Scope Constraints

**Principal constraints:**
```cedar
principal                                // any principal
principal == User::"alice"               // exact match
principal in Group::"admins"             // hierarchy membership
principal is User                        // entity type check
principal is User in Group::"admins"     // type + hierarchy
```

**Action constraints:**
```cedar
action                                   // any action
action == Action::"view"                 // exact match
action in [Action::"view", Action::"edit"]  // set membership
action in Action::"readActions"          // action group
```

**Resource constraints:**
```cedar
resource                                 // any resource
resource == Photo::"vacation.jpg"        // exact match
resource in Album::"vacation"            // hierarchy membership
resource is Photo                        // entity type check
resource is Photo in Album::"vacation"   // type + hierarchy
```

Source: https://docs.cedarpolicy.com/policies/syntax-policy.html

### Condition Clauses

`when` clauses must evaluate to `true` for the policy to apply.
`unless` clauses must evaluate to `false` for the policy to apply.
Multiple conditions are supported on a single policy.

```cedar
permit (
    principal,
    action in [Action::"listPhotos", Action::"view"],
    resource in Album::"device_prototypes"
)
when {
    principal.department == "Engineering" &&
    principal.jobLevel >= 5
}
unless {
    resource.classification == "embargoed"
};
```

Source: https://docs.cedarpolicy.com/policies/policy-examples.html

### Entity Reference Format

Entities are referenced as `EntityType::"entityId"`:

```cedar
User::"alice"
Photo::"VacationPhoto94.jpg"
PhotoFlash::Groups::Album::"vacation"     // namespaced
User::"a1b2c3d4-e5f6-a1b2-c3d4-EXAMPLE11111"  // UUID recommended for production
```

Source: https://docs.cedarpolicy.com/policies/syntax-entity.html

### Operators Available in Conditions

**Comparison**: `==`, `!=`, `<`, `<=`, `>`, `>=`
**Logical**: `&&`, `||`, `!`
**Arithmetic**: `+`, `-`, `*` (integer multiplication only: `n * expr`)
**Hierarchy**: `in` (membership test)
**Type**: `is` (entity type test)
**Attribute**: `.` (dot access), `["key"]` (bracket access), `has` (presence test)
**Tag**: `.hasTag("key")`, `.getTag("key")`
**Set**: `contains`, `containsAll`, `containsAny`
**String**: `like` (glob matching with `*` wildcard)
**Conditional**: `if expr then expr else expr`

Source: https://docs.cedarpolicy.com/policies/syntax-policy.html

### Data Types

| Type | Description | Range/Notes |
|------|-------------|-------------|
| `Bool` | `true` / `false` | |
| `String` | Unicode string | |
| `Long` | 64-bit signed integer | -9223372036854775808 to 9223372036854775807 |
| `Set` | Unordered collection | Validator requires uniform element types |
| `Record` | Named attribute collection | Nested records supported |
| Entity | Reference to principal/action/resource | `Type::"id"` format |
| `datetime` | Millisecond-precision instant | ISO 8601 via `datetime()` constructor |
| `decimal` | Fixed-point (4 decimal places) | via `decimal()` constructor |
| `duration` | Time interval | via `duration()` constructor, e.g. `duration("2h30m")` |
| `ipaddr` | IPv4/IPv6 address or CIDR range | via `ip()` constructor |

Extension types (`datetime`, `decimal`, `duration`, `ipaddr`) require string
literal arguments for validation. Arithmetic overflow on `Long` causes a policy
evaluation error (not a crash -- the policy is skipped per skip-on-error semantics).

Source: https://docs.cedarpolicy.com/policies/syntax-datatypes.html

### Annotations

```cedar
@id("policy-001")
@advice("Contact admin if denied")
@custom_key("custom_value")
permit ( ... );
```

Annotations have no effect on evaluation. They are metadata for external tooling.

---

## 3. Cedar Schema System

Cedar schemas define the structure of entity types, their attributes, and valid
action-entity relationships. Two formats are supported: human-readable Cedar
schema syntax and JSON schema format.

Source: https://docs.cedarpolicy.com/schema/schema.html

### Human-Readable Schema Syntax

Source: https://docs.cedarpolicy.com/schema/human-readable-schema.html

**Namespace declaration:**
```cedar
namespace PhotoApp {
    // all declarations scoped to PhotoApp::
}
```

**Entity type declaration:**
```cedar
entity User in [Group] {
    personalGroup: Group,
    delegate?: User,           // ? marks optional attributes
    blocked: Set<User>,
    age: Long,
    name: String,
} tags String;                 // dynamic key-value tags
```

**Enumerated entity types:**
```cedar
entity Role enum ["admin", "viewer", "editor"];
```

**Action declaration:**
```cedar
action ViewDocument in [ReadActions] appliesTo {
    principal: [User, Public],
    resource: Document,
    context: {
        network: ipaddr,
        browser: String,
    }
};
```

**Common type aliases:**
```cedar
type AuthContext = {
    network: ipaddr,
    browser: String,
    mfaAuthenticated: Bool,
};
```

### Attribute Types Supported in Schema

- Primitives: `Bool`, `String`, `Long`
- Entity references: by type name
- Collections: `Set<Type>`
- Records: `{ name: Type, ... }` with optional fields via `?`
- Extension types: `ipaddr`, `decimal`, `datetime`, `duration`
- Common type aliases via `type Name = ...;`

### Type Resolution Priority

When a name is ambiguous, the parser resolves in this order:
1. Common type name
2. Entity type name
3. Primitive/extension type name

Use `__cedar::` prefix to explicitly reference primitives (e.g., `__cedar::ipaddr`).

### JSON Schema Format

Also supported for machine-generated schemas. Documentation at:
https://docs.cedarpolicy.com/schema/json-schema.html

---

## 4. Authorization Engine / Evaluation Model

Source: https://docs.cedarpolicy.com/auth/authorization.html

### Request Structure (PARC)

Every authorization request is a 4-tuple:

1. **Principal** (`P`): The entity making the request (e.g., `User::"alice"`)
2. **Action** (`A`): The operation attempted (e.g., `Action::"view"`)
3. **Resource** (`R`): The target entity (e.g., `Photo::"pic.jpg"`)
4. **Context** (`C`): Environmental data as a record (e.g., IP address, time)

### Evaluation Algorithm

For a given request, the authorizer:

1. Evaluates **every** policy in the policy set independently
2. For each policy:
   a. Tests the scope (principal, action, resource constraints)
   b. If scope matches, evaluates all `when`/`unless` conditions
   c. Determines if the policy is "satisfied" (scope matches AND all conditions met)
3. Applies the decision algorithm (see Section 5)

Policies do NOT reference or depend on each other. Each is evaluated in isolation.
This enables parallelized evaluation.

### Response Structure

The `Response` contains:
- **Decision**: `Allow` or `Deny`
- **Determining policies**: the set of policy IDs that produced the decision
  - If `Deny` from forbid: the satisfied forbid policies
  - If `Allow`: the satisfied permit policies
  - If `Deny` from default: empty set
- **Error diagnostics**: policy IDs and details for any policies that errored

---

## 5. Default-Deny and Permit/Forbid Interaction

Source: https://docs.cedarpolicy.com/auth/authorization.html

### Three Core Properties

1. **Default deny**: If no policy is satisfied, the decision is `Deny`
2. **Forbid overrides permit**: If ANY `forbid` policy is satisfied, the decision
   is `Deny`, regardless of how many `permit` policies are also satisfied
3. **Skip on error**: If a policy's evaluation produces an error (e.g., attribute
   access on missing field), the policy is skipped -- it does not contribute to
   the decision

### Decision Algorithm (precise)

```
if any forbid policy evaluates to true:
    decision = Deny
else if any permit policy evaluates to true:
    decision = Allow
else:
    decision = Deny   (default deny)
```

### Design Rationale

- Permit policies are the ONLY way to grant access -- easy to audit
- Forbid policies define guardrails that permit policies can never cross
- Forbid policies can be understood independently of any permit policies
- Adding a new permit policy can never override an existing forbid
- Skip-on-error prevents a buggy new policy from causing a global deny

Source: https://docs.cedarpolicy.com/other/security.html

---

## 6. cedar-policy Crate Rust API

Source: https://docs.rs/cedar-policy/latest/cedar_policy/

### Installation

```toml
[dependencies]
cedar-policy = "4.9"
```

### Core Types

```
Authorizer          -- evaluates requests against policies
PolicySet           -- collection of policies and templates
Request             -- PARC authorization request
Entities            -- entity hierarchy (principals, resources, actions)
Context             -- request context record
Schema              -- entity type and action definitions
Response            -- authorization result
EntityUid           -- unique entity identifier (Type::"id")
EntityTypeName      -- entity type name with namespace
Policy              -- a single Cedar policy
Template            -- a policy template with placeholders
Decision            -- Allow or Deny enum
```

### Minimal Example

```rust
use cedar_policy::*;

fn main() {
    // Parse policies from Cedar syntax
    let policy_src = r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == File::"93"
        );
    "#;
    let policies: PolicySet = policy_src.parse().unwrap();

    // Create entity UIDs from strings
    let principal: EntityUid = r#"User::"alice""#.parse().unwrap();
    let action: EntityUid = r#"Action::"view""#.parse().unwrap();
    let resource: EntityUid = r#"File::"93""#.parse().unwrap();

    // Build request (None = no schema validation)
    let request = Request::new(
        principal, action, resource,
        Context::empty(),
        None,  // Option<&Schema>
    ).unwrap();

    // Authorize
    let authorizer = Authorizer::new();
    let entities = Entities::empty();
    let response = authorizer.is_authorized(&request, &policies, &entities);

    assert_eq!(response.decision(), Decision::Allow);
}
```

Source: https://docs.rs/cedar-policy/latest/cedar_policy/ and
https://github.com/cedar-policy/cedar

### Key API Methods

**Authorizer:**
```rust
impl Authorizer {
    pub fn new() -> Self;
    pub fn is_authorized(&self, r: &Request, p: &PolicySet, e: &Entities) -> Response;

    // Experimental (requires "partial-eval" feature)
    pub fn is_authorized_partial(
        &self, query: &Request, policy_set: &PolicySet, entities: &Entities
    ) -> PartialResponse;
}
```
Source: https://docs.rs/cedar-policy/latest/cedar_policy/struct.Authorizer.html

**Request:**
```rust
impl Request {
    pub fn new(
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        schema: Option<&Schema>,
    ) -> Result<Self, RequestValidationError>;

    // Experimental (requires "partial-eval" feature)
    pub fn builder() -> RequestBuilder<UnsetSchema>;

    pub fn principal(&self) -> Option<&EntityUid>;
    pub fn action(&self) -> Option<&EntityUid>;
    pub fn resource(&self) -> Option<&EntityUid>;
    pub fn context(&self) -> Option<&Context>;
}
```
Source: https://docs.rs/cedar-policy/latest/cedar_policy/struct.Request.html

**PolicySet:**
```rust
impl PolicySet {
    pub fn new() -> Self;
    pub fn from_policies(policies: impl IntoIterator<Item = Policy>)
        -> Result<Self, PolicySetError>;
    pub fn from_json_str(src: impl AsRef<str>) -> Result<Self, PolicySetError>;
    pub fn from_json_value(src: Value) -> Result<Self, PolicySetError>;
    pub fn from_json_file(r: impl Read) -> Result<Self, PolicySetError>;

    pub fn add(&mut self, policy: Policy) -> Result<(), PolicySetError>;
    pub fn remove_static(&mut self, id: PolicyId) -> Result<Policy, PolicySetError>;
    pub fn policy(&self, id: &PolicyId) -> Option<&Policy>;
    pub fn policies(&self) -> impl Iterator<Item = &Policy>;
    pub fn is_empty(&self) -> bool;
    pub fn num_of_policies(&self) -> usize;

    // Template operations
    pub fn add_template(&mut self, t: Template) -> Result<(), PolicySetError>;
    pub fn link(
        &mut self, template_id: PolicyId, new_id: PolicyId,
        vals: HashMap<SlotId, EntityUid>
    ) -> Result<(), PolicySetError>;
    pub fn unlink(&mut self, id: PolicyId) -> Result<Policy, PolicySetError>;
    pub fn templates(&self) -> impl Iterator<Item = &Template>;

    // Merge
    pub fn merge(
        &mut self, other: &Self, rename_duplicates: bool
    ) -> Result<HashMap<PolicyId, PolicyId>, PolicySetError>;

    // Serialization
    pub fn to_json(self) -> Result<Value, PolicySetError>;
    pub fn to_cedar(&self) -> Option<String>;
}
```

Also implements `FromStr` for parsing Cedar syntax directly:
```rust
let policies: PolicySet = cedar_source_string.parse().unwrap();
```
Source: https://docs.rs/cedar-policy/latest/cedar_policy/struct.PolicySet.html

**Entities:**
```rust
impl Entities {
    pub fn empty() -> Self;
    pub fn from_json_str(json: &str, schema: Option<&Schema>)
        -> Result<Self, EntitiesError>;
    pub fn from_json_value(json: Value, schema: Option<&Schema>)
        -> Result<Self, EntitiesError>;
    pub fn from_json_file(json: impl Read, schema: Option<&Schema>)
        -> Result<Self, EntitiesError>;
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
        schema: Option<&Schema>
    ) -> Result<Self, EntitiesError>;

    pub fn add_entities(/* ... */) -> Result<(), EntitiesError>;
    pub fn remove_entities(/* ... */) -> Result<(), EntitiesError>;
    pub fn upsert_entities(/* ... */) -> Result<(), EntitiesError>;

    pub fn get(&self, uid: &EntityUid) -> Option<&Entity>;
    pub fn iter(&self) -> impl Iterator<Item = &Entity>;
    pub fn ancestors(&self, euid: &EntityUid) -> /* iterator */;
    pub fn is_ancestor_of(&self, a: &EntityUid, b: &EntityUid) -> bool;
}
```
Source: https://docs.rs/cedar-policy/latest/cedar_policy/struct.Entities.html

### Feature Flags

| Feature | Purpose |
|---------|---------|
| `partial-eval` | Enables `is_authorized_partial()` and `RequestBuilder` |
| `tpe` | Type-aware partial evaluation (RFC 95) -- `query_resource()`, `query_principal()`, `query_action()` |

Both are marked experimental.

### Partial Evaluation (Experimental)

Partial evaluation allows authorization with unknown values, producing either a
concrete `Allow`/`Deny` or residual policies that capture remaining constraints.

Use cases:
- **Access enumeration**: "What resources can Alice access?" -- leave resource unknown
- **Data filtering**: Convert residual policies to database queries
- **Deferred evaluation**: Separate known from context-dependent checks

```rust
// Enable in Cargo.toml:
// cedar-policy = { version = "4.9", features = ["partial-eval"] }

let request = Request::builder()
    .principal(Some(principal))
    .action(Some(action))
    // resource left as None = unknown
    .context(context)
    .build()
    .unwrap();

match authorizer.is_authorized_partial(&request, &policies, &entities) {
    PartialResponse::Concrete(r) => println!("Decision: {:?}", r.decision()),
    PartialResponse::Residual(r) => {
        for policy in r.residuals().policies() {
            println!("Residual: {policy}");
        }
    }
}
```

Source: https://cedarland.blog/usage/partial-evaluation/content.html

---

## 7. Performance Characteristics

### Computational Complexity

From the academic paper (https://arxiv.org/pdf/2403.04651):

- **Common case**: O(n) where n is total size of policies and entities
- **Worst case**: O(n^2) due to set containment operations (`containsAll`, `containsAny`)
- **No loops**: Cedar deliberately excludes loops to guarantee bounded latency
- **No stateful operations**: Enables parallelized policy evaluation
- **Termination guaranteed**: Every policy evaluation terminates

### Latency Numbers

- **Sub-millisecond evaluation** is consistently reported, even with hundreds of
  policies in the set.
  Source: https://www.strongdm.com/cedar-policy-language

- **Comparative benchmarks** (from Teleport security benchmarking):
  - Cedar authorizer is **28.7x-35.2x faster than OpenFGA**
  - Cedar authorizer is **42.8x-80.8x faster than OPA/Rego**
  - Templates-based encoding provides **10.0x-18.0x** additional speedup
  Source: https://goteleport.com/blog/benchmarking-policy-languages/

- **Formal model execution**: The Lean formal model executes in approximately
  **5 microseconds per test case**, enabling millions of differential tests
  Source: https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing

### Policy Compression

- Cedar policies with 50+ policies achieve **>80% space savings** when compressed
- Smaller policy sets maintain **~50% compression rate** with pre-built dictionaries
  Source: https://www.strongdm.com/cedar-policy-language

[UNVERIFIED] Specific p50/p95/p99 latency numbers at various policy set sizes were
not found in publicly accessible benchmarks. The Teleport blog post structure could
not be fully extracted. The "sub-millisecond" claim is widely repeated but lacks
published percentile breakdowns from the Cedar team.

---

## 8. Limitations and Known Issues

### Deliberate Language Restrictions

These are by design, not bugs:

1. **No loops or recursion**: Cedar policies cannot iterate. This is intentional
   to guarantee termination and bound latency. You cannot write "for each item
   in list, check X."
   Source: https://arxiv.org/pdf/2403.04651

2. **No external data fetching**: Policies cannot call APIs, query databases, or
   access anything outside the PARC request and entity hierarchy. All data must
   be provided upfront.
   Source: https://docs.cedarpolicy.com/auth/authorization.html

3. **Boolean-only decisions**: Cedar produces only `Allow` or `Deny`. It cannot
   return structured data, scores, filtered lists, or conditional payloads. If you
   need "allow with rate limit X", that logic must live outside Cedar.
   Source: https://arxiv.org/pdf/2403.04651

4. **No custom functions**: You cannot define functions or macros in Cedar. The
   language is intentionally not Turing-complete.

5. **Rudimentary string matching**: Only `like` with `*` glob patterns. No regex,
   no substring operations, no string manipulation.
   Source: https://arxiv.org/pdf/2403.04651 ("Cedar has rudimentary string matching")

6. **Set search limited to membership**: `contains`, `containsAll`, `containsAny`
   are the only set operations. No filtering, mapping, or aggregation.
   Source: https://arxiv.org/pdf/2403.04651

7. **No integer division or modulo**: Arithmetic is limited to `+`, `-`, `*`
   (and `*` only as `integer * expr`). No `/` or `%`.

### Ecosystem Limitations

8. **Smaller ecosystem than OPA**: Fewer third-party integrations, fewer
   community-maintained policy libraries, less battle-hardened operational tooling.
   Source: https://www.permit.io/blog/policy-engines

9. **No built-in policy management APIs**: Unlike OPA (which ships with HTTP APIs
   for policy and data management), Cedar is "just a library." You must build your
   own policy storage, distribution, and management layer.
   Source: https://www.styra.com/blog/comparing-opa-rego-to-aws-cedar-and-google-zanzibar/

10. **No built-in RBAC role assignment**: Cedar evaluates policies but does not
    manage role-to-user mappings. Your application must maintain and provide the
    entity hierarchy.

11. **Partial evaluation is experimental**: The `partial-eval` and `tpe` features
    are not stabilized. API may change between versions.

12. **Initial setup complexity**: Requires understanding the entity model, schema
    system, and PARC request structure before you can write effective policies.
    Source: https://www.strongdm.com/cedar-policy-language

### Validator Limitations

13. **Validator rejects valid programs**: The type checker is conservative. Some
    expressions that evaluate correctly will be flagged as type errors. Example:
    empty set literals in policies are rejected by the validator (though they work
    in entities/context).
    Source: https://docs.cedarpolicy.com/policies/syntax-datatypes.html

14. **Mixed-type sets rejected**: The validator requires all set elements to have
    the same type, even though the evaluator handles mixed-type sets fine.
    Source: https://docs.cedarpolicy.com/policies/syntax-datatypes.html

---

## 9. Cedar vs OPA/Rego Comparison

### Architecture Comparison

| Dimension | Cedar | OPA/Rego |
|-----------|-------|----------|
| **Language type** | Domain-specific (authorization only) | General-purpose policy language |
| **Language family** | Functional, custom | Datalog/Prolog derivative |
| **Decision output** | Boolean (Allow/Deny) | Arbitrary JSON |
| **Deployment** | Library (embed in your service) | Sidecar/daemon with HTTP API |
| **Primary use case** | Application-level authorization | Infrastructure-wide policy |
| **Authorization model** | RBAC + ABAC native, ReBAC encodable | RBAC + ABAC + arbitrary |
| **Turing-complete** | No (by design) | Practically yes |
| **Formal verification** | Lean proofs + SMT analysis | No formal verification |
| **Schema validation** | Built-in, sound validator | Optional via `rego.v1` |
| **Community size** | Smaller, growing | Large, mature (Netflix, Pinterest, Goldman) |
| **K8s integration** | cedar-access-control-for-k8s (newer) | Gatekeeper (mature) |

Sources:
- https://www.permit.io/blog/policy-engine-showdown-opa-vs-openfga-vs-cedar
- https://www.styra.com/blog/comparing-opa-rego-to-aws-cedar-and-google-zanzibar/
- https://www.osohq.com/learn/opa-vs-cedar-vs-zanzibar

### Performance

- Cedar is **42x-81x faster** than Rego for authorization decisions
  Source: https://goteleport.com/blog/benchmarking-policy-languages/
- OPA requires ~30-40 hours to learn Rego proficiently
  Source: https://www.permit.io/blog/policy-engine-showdown-opa-vs-openfga-vs-cedar

### When to Choose Cedar

- Application-level fine-grained authorization (your use case)
- Team wants readable, auditable policies non-engineers can review
- Performance is critical (sub-ms latency requirement)
- You want formal safety guarantees (no unbounded evaluation)
- Rust service (native library, no sidecar overhead)
- You are OK building your own policy management layer

### When to Choose OPA

- Infrastructure policy (K8s admission, Terraform, CI/CD)
- Need arbitrary structured decisions (not just allow/deny)
- Need built-in policy management HTTP APIs
- Team has existing Rego expertise
- Need extensive built-in function library
- Need to enforce policies across heterogeneous infrastructure

### Concrete Tradeoff for Kong PDP Use Case

Cedar is the stronger choice for an API gateway PDP because:
1. The PARC model maps directly to HTTP requests (principal=caller, action=method,
   resource=path, context=headers/claims)
2. Sub-ms evaluation adds minimal latency to the request path
3. Rust-native library means no IPC/sidecar overhead
4. Default-deny + forbid-overrides-permit matches API security expectations
5. Schema validation catches policy errors at deploy time, not runtime
6. The entity hierarchy naturally models API resource trees

OPA would be the choice if the PDP also needed to enforce non-authorization
policies (rate limiting decisions, request transformation rules, etc.) or if the
team already had Rego expertise.

---

## 10. Amazon Verified Permissions (AVP) and Open-Source Cedar

Source: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html

### Relationship

- **Cedar** is the open-source language and engine (Apache 2.0)
- **Amazon Verified Permissions** is a managed AWS service that uses Cedar
- AVP adds: managed policy storage, API endpoints, Cognito integration, audit logging
- AVP is to Cedar what RDS is to PostgreSQL -- a managed deployment option

### AVP Restrictions vs Open-Source Cedar

Source: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/getting-started-differences-verifiedpermissions-cedar.html

| Feature | Open-Source Cedar | AVP |
|---------|-------------------|-----|
| Namespaces | Multiple allowed | One per policy store |
| Policy templates | Principal OR resource can be unconstrained | Both MUST be constrained |
| Schema key names | Any string including empty | Non-empty strings only |
| Action group entities | Must be manually included | Auto-appended from schema |
| Entity JSON format | Standard Cedar JSON | AVP-specific format with type wrappers |
| Policy size | Unlimited | 10,000 bytes max |
| Schema size | Unlimited | 100,000 bytes max |
| Entity ID length | Unlimited | 200 bytes max |

### AVP Entity JSON Difference

AVP wraps scalar values differently:
```json
// Cedar open-source
{ "number": 1 }

// AVP format
{ "Record": { "number": { "Long": 1 } } }
```

### Cedar Version in AVP

AVP currently supports Cedar 4.7 (upgraded from Cedar 2).
Source: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/cedar4-faq.html

### Relevance to rust-pdp

For a self-hosted Kong PDP, you use the open-source `cedar-policy` crate directly.
AVP is irrelevant unless you want AWS-managed policy storage. The open-source crate
has no AWS dependencies and no network requirements.

---

## 11. Formal Verification and Analysis Tools

Sources:
- https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing
- https://lean-lang.org/use-cases/cedar/
- https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/

### Verification-Guided Development

Cedar is built using a dual implementation approach:

1. **Lean formal model**: Executable formal specification of the evaluator,
   authorizer, and validator. Correctness properties are proved as Lean theorems.
2. **Rust production implementation**: The shipping code.
3. **Differential testing**: Millions of random inputs are run through both
   implementations to verify identical output.

### Key Proofs

- **Validator soundness**: If the validator accepts a policy against a schema,
  evaluating that policy will never produce certain classes of errors (type errors,
  missing attribute errors).
- **Symbolic compiler soundness and completeness**: The SMT encoding faithfully
  represents Cedar semantics.
- **Authorization algorithm correctness**: The three properties (default deny,
  forbid overrides, skip on error) are formally proved.

### Cedar Analysis Tools

The `cedar-policy-symcc` crate (symbolic compiler) translates Cedar policies to
SMT-LIB format for automated reasoning. This enables:

- **Policy diffing**: "Does policy set A authorize strictly more requests than B?"
- **Redundancy detection**: "Is this policy redundant given the other policies?"
- **Reachability analysis**: "Can this forbid policy ever be triggered?"
- **Property verification**: "Is it true that no policy grants admin access
  without MFA?"

The encoding is **sound, complete, and decidable** -- the SMT solver will always
terminate with a correct answer.

---

## 12. Practical Integration Notes for Kong PDP

### Entity Mapping for API Gateway

```
Principal types:  ApiClient, ServiceAccount, User
Action types:     Action::"GET", Action::"POST", Action::"PUT", Action::"DELETE"
Resource types:   Endpoint::"path/to/resource", Api::"service-name"
Context:          JWT claims, IP address, request headers, rate limit state
```

### Schema Example for API Gateway

```cedar
namespace ApiGateway {
    entity ApiClient in [ClientGroup] {
        roles: Set<String>,
        tier: String,
        rateLimit: Long,
    };

    entity ServiceAccount in [ClientGroup] {
        service: String,
        environment: String,
    };

    entity ClientGroup;

    entity Endpoint in [Api] {
        path: String,
        public: Bool,
    };

    entity Api;

    action GET, POST, PUT, DELETE, PATCH appliesTo {
        principal: [ApiClient, ServiceAccount],
        resource: [Endpoint],
        context: {
            sourceIp: ipaddr,
            jwt_sub: String,
            jwt_iss: String,
        },
    };
}
```

### Policy Examples for API Gateway

```cedar
// Public endpoints -- no auth required
permit (
    principal,
    action,
    resource
)
when { resource.public == true };

// Admin-only endpoints
permit (
    principal,
    action,
    resource in Api::"admin-api"
)
when { principal.roles.contains("admin") };

// IP allowlist for internal services
forbid (
    principal is ServiceAccount,
    action,
    resource
)
unless { context.sourceIp.isInRange(ip("10.0.0.0/8")) };

// Rate-limited tier access
permit (
    principal,
    action == Action::"GET",
    resource in Api::"public-api"
)
when { principal.tier == "free" || principal.tier == "pro" };
```

### Embedding Pattern

```rust
use cedar_policy::*;
use std::sync::Arc;

struct CedarPdp {
    authorizer: Authorizer,
    policies: Arc<PolicySet>,
    schema: Arc<Schema>,
}

impl CedarPdp {
    fn authorize(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        entities: &Entities,
    ) -> (Decision, Vec<PolicyId>) {
        let request = Request::new(
            principal, action, resource, context,
            Some(&self.schema),
        ).expect("request validation failed");

        let response = self.authorizer.is_authorized(
            &request, &self.policies, entities,
        );

        let determining: Vec<PolicyId> = response
            .diagnostics()
            .reason()
            .cloned()
            .collect();

        (response.decision(), determining)
    }
}
```

Note: `Authorizer::new()` manages its own stack size via the `stacker` crate.
It implements `Clone`, `Debug`, `Default` -- safe to share across threads behind
an `Arc`.

---

## Source Index

All sources referenced in this document:

- Cedar GitHub: https://github.com/cedar-policy/cedar
- Cedar docs: https://docs.cedarpolicy.com/
- Cedar crates.io: https://crates.io/crates/cedar-policy
- Cedar Rust API docs: https://docs.rs/cedar-policy/latest/cedar_policy/
- Cedar academic paper: https://dl.acm.org/doi/10.1145/3649835
- Cedar paper (arXiv): https://arxiv.org/pdf/2403.04651
- Cedar verification blog: https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing
- Cedar Lean case study: https://lean-lang.org/use-cases/cedar/
- Cedar analysis tools: https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/
- Cedar syntax: https://docs.cedarpolicy.com/policies/syntax-policy.html
- Cedar data types: https://docs.cedarpolicy.com/policies/syntax-datatypes.html
- Cedar entities: https://docs.cedarpolicy.com/policies/syntax-entity.html
- Cedar schema: https://docs.cedarpolicy.com/schema/human-readable-schema.html
- Cedar authorization: https://docs.cedarpolicy.com/auth/authorization.html
- Cedar security: https://docs.cedarpolicy.com/other/security.html
- Cedar terminology: https://docs.cedarpolicy.com/overview/terminology.html
- Authorizer API: https://docs.rs/cedar-policy/latest/cedar_policy/struct.Authorizer.html
- Request API: https://docs.rs/cedar-policy/latest/cedar_policy/struct.Request.html
- PolicySet API: https://docs.rs/cedar-policy/latest/cedar_policy/struct.PolicySet.html
- Entities API: https://docs.rs/cedar-policy/latest/cedar_policy/struct.Entities.html
- Partial evaluation guide: https://cedarland.blog/usage/partial-evaluation/content.html
- AVP docs: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html
- AVP Cedar differences: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/getting-started-differences-verifiedpermissions-cedar.html
- AVP Cedar 4 FAQ: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/cedar4-faq.html
- Teleport benchmarks: https://goteleport.com/blog/benchmarking-policy-languages/
- Permit.io comparison: https://www.permit.io/blog/policy-engine-showdown-opa-vs-openfga-vs-cedar
- Permit.io engine guide: https://www.permit.io/blog/policy-engines
- Oso comparison: https://www.osohq.com/learn/opa-vs-cedar-vs-zanzibar
- Styra comparison: https://www.styra.com/blog/comparing-opa-rego-to-aws-cedar-and-google-zanzibar/
- StrongDM guide: https://www.strongdm.com/cedar-policy-language
- Cedarland blog: https://cedarland.blog/usage/partial-evaluation/content.html
- Cedar K8s: https://github.com/cedar-policy/cedar-access-control-for-k8s
- Cedar auth service example: https://github.com/Pigius/cedar-authorization-service
