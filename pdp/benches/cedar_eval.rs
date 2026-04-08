use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    Schema,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashSet;
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

criterion_group!(benches, bench_cedar_eval);
criterion_main!(benches);
