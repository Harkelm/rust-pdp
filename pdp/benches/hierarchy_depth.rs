use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    Schema,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashSet;
use std::str::FromStr;

const HIERARCHY_SCHEMA: &str = r#"
entity Role in [Role];
entity User in [Role];
entity Resource;
action "read" appliesTo { principal: [User], resource: [Resource] };
"#;

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

/// Build a linear role chain of depth N:
///   Role_0 in [Role_1], Role_1 in [Role_2], ..., Role_{N-1} in [Role_N]
///   User in [Role_0]
/// Policy: permit(principal in Role::"role-{N}", action == Action::"read", resource == Resource::"/test")
/// Plus 9 noise policies for other users.
fn build_hierarchy_scenario(depth: usize) -> (PolicySet, Entities, Request) {
    // Build role entities with linear parentage
    let mut entities_vec: Vec<Entity> = Vec::new();

    // Create roles from N down to 0
    // Role_N has no parents (top of chain)
    let top_uid = make_uid("Role", &format!("role-{depth}"));
    entities_vec.push(Entity::new_no_attrs(top_uid, HashSet::new()));

    // Role_{i} in [Role_{i+1}] for i = N-1 down to 0
    for i in (0..depth).rev() {
        let uid = make_uid("Role", &format!("role-{i}"));
        let parent_uid = make_uid("Role", &format!("role-{}", i + 1));
        let mut parents = HashSet::new();
        parents.insert(parent_uid);
        entities_vec.push(Entity::new_no_attrs(uid, parents));
    }

    // User in [Role_0]
    let user_uid = make_uid("User", "bench-user");
    let role_0_uid = make_uid("Role", "role-0");
    let mut user_parents = HashSet::new();
    user_parents.insert(role_0_uid);
    entities_vec.push(Entity::new_no_attrs(user_uid, user_parents));

    // Resource
    let resource_uid = make_uid("Resource", "/test");
    entities_vec.push(Entity::new_no_attrs(resource_uid, HashSet::new()));

    let schema = Schema::from_cedarschema_str(HIERARCHY_SCHEMA)
        .expect("valid schema")
        .0;
    let entities = Entities::from_entities(entities_vec, Some(&schema)).expect("valid entities");

    // Policy: hierarchy check + 9 noise permits
    let mut policy_src = format!(
        "permit(principal in Role::\"role-{depth}\", action == Action::\"read\", resource == Resource::\"/test\");\n"
    );
    for i in 0..9 {
        policy_src.push_str(&format!(
            "permit(principal == User::\"noise-{i}\", action == Action::\"read\", resource == Resource::\"/noise-{i}\");\n"
        ));
    }
    let policy_set = policy_src.parse::<PolicySet>().expect("valid policies");

    let principal = make_uid("User", "bench-user");
    let action = make_uid("Action", "read");
    let resource = make_uid("Resource", "/test");
    let request = Request::new(principal, action, resource, Context::empty(), None)
        .expect("valid request");

    (policy_set, entities, request)
}

fn bench_hierarchy_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("hierarchy_depth");
    let authorizer = Authorizer::new();

    for depth in [1usize, 2, 5, 10, 15, 20] {
        let (policy_set, entities, request) = build_hierarchy_scenario(depth);

        group.bench_function(BenchmarkId::new("depth", depth), |b| {
            b.iter(|| authorizer.is_authorized(&request, &policy_set, &entities));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_hierarchy_depth);
criterion_main!(benches);
