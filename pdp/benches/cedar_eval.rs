use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

/// Cedar schema for benchmarks: no namespace, simple User/Resource entities
/// with read and write actions.
const BENCH_SCHEMA: &str = r#"
entity User;
entity Resource;
action "read" appliesTo { principal: [User], resource: [Resource] };
action "write" appliesTo { principal: [User], resource: [Resource] };
"#;

fn make_entity_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

/// Generate N permit policies. Policy i permits user-i to read /resource-i.
/// Policy 0 is always included so the benchmark request always matches exactly
/// one policy.
fn generate_policy_set(n: usize) -> PolicySet {
    let mut src = String::new();
    for i in 0..n {
        src.push_str(&format!(
            r#"permit(principal == User::"user-{i}", action == Action::"read", resource == Resource::"/resource-{i}");"#,
            i = i
        ));
        src.push('\n');
    }
    src.parse::<PolicySet>().expect("valid policy set")
}

/// Generate N User entities with no attributes and no parents.
fn generate_entities(n: usize) -> Entities {
    let mut entity_vec: Vec<Entity> = Vec::new();
    for i in 0..n {
        let uid = make_entity_uid("User", &format!("user-{}", i));
        entity_vec.push(Entity::new_no_attrs(uid, HashSet::new()));
    }
    // Also add Resource entities so the entity set is non-trivial.
    for i in 0..n {
        let uid = make_entity_uid("Resource", &format!("/resource-{}", i));
        entity_vec.push(Entity::new_no_attrs(uid, HashSet::new()));
    }
    Entities::from_entities(entity_vec, None).expect("valid entities")
}

fn build_schema() -> Schema {
    Schema::from_cedarschema_str(BENCH_SCHEMA)
        .expect("valid schema")
        .0
}

/// Build a Cedar Request for user-0 reading /resource-0.
/// This matches exactly one policy in any policy set generated above.
fn build_request() -> Request {
    let principal = make_entity_uid("User", "user-0");
    let action = make_entity_uid("Action", "read");
    let resource = make_entity_uid("Resource", "/resource-0");
    let context = Context::empty();
    Request::new(principal, action, resource, context, None).expect("valid request")
}

fn bench_cedar_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("cedar_evaluation");

    // Pre-build schema (shared -- schema is Clone-able via Arc internally)
    let _schema = build_schema();

    for policy_count in [10usize, 100, 1000] {
        for entity_count in [10usize, 100, 1000] {
            // Build all fixtures outside the timed loop.
            let policy_set = generate_policy_set(policy_count);
            let entities = generate_entities(entity_count);
            let request = build_request();
            let authorizer = Authorizer::new();

            group.bench_function(
                BenchmarkId::new(
                    format!("policies_{}_entities_{}", policy_count, entity_count),
                    "",
                ),
                |b| {
                    b.iter(|| {
                        authorizer.is_authorized(&request, &policy_set, &entities)
                    });
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Realistic evaluation group -- production schema + policies, 6 scenarios
// ---------------------------------------------------------------------------

const PROD_SCHEMA: &str = include_str!("../../policies/api_gateway.cedarschema");

const POLICY_RBAC: &str = include_str!("../../policies/rbac_route_access.cedar");
const POLICY_TIER: &str = include_str!("../../policies/subscription_tier_gating.cedar");
const POLICY_ORG: &str = include_str!("../../policies/org_scoped_access.cedar");
const POLICY_SUSPENDED: &str = include_str!("../../policies/suspended_account_deny.cedar");
const POLICY_TEMPLATE: &str = include_str!("../../policies/template_resource_access.cedar");
const POLICY_SCOPE: &str = include_str!("../../policies/data_scope_access.cedar");

fn prod_schema() -> Schema {
    Schema::from_cedarschema_str(PROD_SCHEMA)
        .expect("valid production schema")
        .0
}

fn prod_policy_set() -> PolicySet {
    let combined = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        POLICY_RBAC, POLICY_TIER, POLICY_ORG, POLICY_SUSPENDED, POLICY_TEMPLATE, POLICY_SCOPE
    );
    combined.parse::<PolicySet>().expect("valid production policies")
}

fn make_ns_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

/// Build a User entity with full attributes for the realistic benchmarks.
fn make_user(
    id: &str,
    roles: &[&str],
    org: &str,
    department: &str,
    scopes: &[&str],
    tier: &str,
    suspended: bool,
) -> (Entity, Vec<Entity>, Entity) {
    // Role entities
    let mut role_entities = Vec::new();
    let mut parents: HashSet<EntityUid> = HashSet::new();
    for role in roles {
        let uid = make_ns_uid("ApiGateway::Role", role);
        parents.insert(uid.clone());
        role_entities.push(Entity::new_no_attrs(uid, HashSet::new()));
    }

    // Org entity
    let org_uid = make_ns_uid("ApiGateway::Organization", org);
    parents.insert(org_uid.clone());
    let org_entity = Entity::new_no_attrs(org_uid, HashSet::new());

    // User entity with attributes
    let user_uid = make_ns_uid("ApiGateway::User", id);
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert("email".to_string(), RestrictedExpression::new_string(format!("{id}@example.com")));
    attrs.insert("department".to_string(), RestrictedExpression::new_string(department.to_string()));
    attrs.insert("org".to_string(), RestrictedExpression::new_string(org.to_string()));
    attrs.insert("subscription_tier".to_string(), RestrictedExpression::new_string(tier.to_string()));
    attrs.insert("suspended".to_string(), RestrictedExpression::new_bool(suspended));
    let scope_exprs: Vec<RestrictedExpression> = scopes.iter().map(|s| RestrictedExpression::new_string(s.to_string())).collect();
    attrs.insert("allowed_scopes".to_string(), RestrictedExpression::new_set(scope_exprs));

    let user_entity = Entity::new(user_uid, attrs, parents).expect("valid user entity");
    (user_entity, role_entities, org_entity)
}

/// Build an ApiResource entity.
fn make_resource(path: &str, service: &str, department: &str, classification: &str, owner_org: &str) -> Entity {
    let uid = make_ns_uid("ApiGateway::ApiResource", path);
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert("service".to_string(), RestrictedExpression::new_string(service.to_string()));
    attrs.insert("path_pattern".to_string(), RestrictedExpression::new_string(path.to_string()));
    attrs.insert("department".to_string(), RestrictedExpression::new_string(department.to_string()));
    attrs.insert("classification".to_string(), RestrictedExpression::new_string(classification.to_string()));
    attrs.insert("owner_org".to_string(), RestrictedExpression::new_string(owner_org.to_string()));
    Entity::new(uid, attrs, HashSet::new()).expect("valid resource entity")
}

/// Assemble Entities from user components + resource.
fn assemble_entities(
    user: Entity,
    role_entities: Vec<Entity>,
    org_entity: Entity,
    resource: Entity,
    schema: Option<&Schema>,
) -> Entities {
    let mut all = Vec::new();
    all.push(user);
    all.extend(role_entities);
    all.push(org_entity);
    all.push(resource);
    Entities::from_entities(all, schema).expect("valid entities")
}

fn make_request(principal_id: &str, action: &str, resource_path: &str) -> Request {
    let principal = make_ns_uid("ApiGateway::User", principal_id);
    let action_uid = make_ns_uid("ApiGateway::Action", action);
    let resource = make_ns_uid("ApiGateway::ApiResource", resource_path);
    Request::new(principal, action_uid, resource, Context::empty(), None).expect("valid request")
}

/// Generate N noise policies (simple permits for distinct users).
fn noise_policies(n: usize) -> String {
    let mut src = String::new();
    for i in 0..n {
        src.push_str(&format!(
            "permit(principal == ApiGateway::User::\"noise-user-{i}\", action == ApiGateway::Action::\"read\", resource is ApiGateway::ApiResource);\n"
        ));
    }
    src
}

fn bench_realistic_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_evaluation");
    let schema = prod_schema();
    let policy_set = prod_policy_set();
    let authorizer = Authorizer::new();

    // Shared resource for most scenarios
    let default_resource = make_resource("/api/v1/users", "user-service", "engineering", "internal", "acme");

    // --- Scenario 1: admin_read ---
    {
        let (user, roles, org) = make_user("bench-admin", &["admin"], "acme", "engineering", &["internal"], "enterprise", false);
        let entities = assemble_entities(user, roles, org, default_resource.clone(), Some(&schema));
        let request = make_request("bench-admin", "read", "/api/v1/users");
        group.bench_function("admin_read", |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    // --- Scenario 2: viewer_delete_deny ---
    {
        let (user, roles, org) = make_user("bench-viewer", &["viewer"], "acme", "engineering", &["internal"], "basic", false);
        let entities = assemble_entities(user, roles, org, default_resource.clone(), Some(&schema));
        let request = make_request("bench-viewer", "delete", "/api/v1/users");
        group.bench_function("viewer_delete_deny", |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    // --- Scenario 3: suspended_admin_deny ---
    {
        let (user, roles, org) = make_user("bench-suspended", &["admin"], "acme", "engineering", &["internal"], "enterprise", true);
        let entities = assemble_entities(user, roles, org, default_resource.clone(), Some(&schema));
        let request = make_request("bench-suspended", "read", "/api/v1/users");
        group.bench_function("suspended_admin_deny", |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    // --- Scenario 4: data_scope_allow ---
    {
        let (user, roles, org) = make_user("bench-scoped", &["viewer"], "acme", "engineering", &["internal", "public"], "basic", false);
        let entities = assemble_entities(user, roles, org, default_resource.clone(), Some(&schema));
        let request = make_request("bench-scoped", "read", "/api/v1/users");
        group.bench_function("data_scope_allow", |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    // --- Scenario 5: cross_org_deny ---
    {
        let cross_org_resource = make_resource("/api/v1/users", "user-service", "engineering", "internal", "other-corp");
        let (user, roles, org) = make_user("bench-crossorg", &["viewer"], "acme", "engineering", &["internal"], "basic", false);
        let entities = assemble_entities(user, roles, org, cross_org_resource, Some(&schema));
        let request = make_request("bench-crossorg", "read", "/api/v1/users");
        group.bench_function("cross_org_deny", |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    // --- Scenario 6: multi_role_write ---
    {
        let (user, roles, org) = make_user("bench-multirole", &["editor", "viewer"], "acme", "engineering", &["internal"], "professional", false);
        let entities = assemble_entities(user, roles, org, default_resource.clone(), Some(&schema));
        let request = make_request("bench-multirole", "write", "/api/v1/users");
        group.bench_function("multi_role_write", |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    // --- Scaling variant: admin_read with noise policies ---
    for noise_count in [100usize, 500, 1000] {
        let noise_src = noise_policies(noise_count);
        let combined_src = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            POLICY_RBAC, POLICY_TIER, POLICY_ORG, POLICY_SUSPENDED, POLICY_TEMPLATE, POLICY_SCOPE, noise_src
        );
        let scaled_policies = combined_src.parse::<PolicySet>().expect("valid scaled policy set");

        let (user, roles, org) = make_user("bench-admin", &["admin"], "acme", "engineering", &["internal"], "enterprise", false);
        let entities = assemble_entities(user, roles, org, default_resource.clone(), Some(&schema));
        let request = make_request("bench-admin", "read", "/api/v1/users");

        group.bench_function(
            BenchmarkId::new("admin_read_noise", noise_count),
            |b| {
                b.iter(|| authorizer.is_authorized(&request, &scaled_policies, &entities));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_cedar_eval, bench_realistic_evaluation);
criterion_main!(benches);
