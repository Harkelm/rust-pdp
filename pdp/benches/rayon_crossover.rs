//! Rayon crossover benchmark -- validates the RAYON_THRESHOLD=4 choice.
//!
//! Measures sequential vs rayon parallel evaluation at batch sizes 1-10 to find
//! the exact crossover point where parallelism pays off. The production code
//! (handlers.rs) hard-codes RAYON_THRESHOLD=4. This benchmark verifies that
//! threshold is correct for the current hardware and policy set.
//!
//! Key question: at what batch size does rayon's fork/join overhead break even
//! with sequential evaluation? The answer depends on per-item eval cost, which
//! depends on policy complexity. We measure with production policies.

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

const PROD_SCHEMA: &str = include_str!("../../policies/api_gateway.cedarschema");
const POLICY_RBAC: &str = include_str!("../../policies/rbac_route_access.cedar");
const POLICY_TIER: &str = include_str!("../../policies/subscription_tier_gating.cedar");
const POLICY_ORG: &str = include_str!("../../policies/org_scoped_access.cedar");
const POLICY_SUSPENDED: &str = include_str!("../../policies/suspended_account_deny.cedar");
const POLICY_TEMPLATE: &str = include_str!("../../policies/template_resource_access.cedar");
const POLICY_SCOPE: &str = include_str!("../../policies/data_scope_access.cedar");

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

fn prod_schema() -> Schema {
    Schema::from_cedarschema_str(PROD_SCHEMA).expect("valid schema").0
}

fn prod_policies() -> PolicySet {
    format!(
        "{POLICY_RBAC}\n{POLICY_TIER}\n{POLICY_ORG}\n{POLICY_SUSPENDED}\n{POLICY_TEMPLATE}\n{POLICY_SCOPE}"
    )
    .parse()
    .expect("valid policies")
}

/// Build a realistic scenario (admin read, Allow path) for one batch item.
fn build_scenario(idx: usize, schema: &Schema) -> (Entities, Request) {
    let user_id = format!("crossover-user-{idx}");

    let admin_uid = make_uid("ApiGateway::Role", "admin");
    let admin_entity = Entity::new_no_attrs(admin_uid.clone(), HashSet::new());

    let org_uid = make_uid("ApiGateway::Organization", "acme");
    let org_entity = Entity::new_no_attrs(org_uid.clone(), HashSet::new());

    let user_uid = make_uid("ApiGateway::User", &user_id);
    let mut parents = HashSet::new();
    parents.insert(admin_uid);
    parents.insert(org_uid);

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert("email".into(), RestrictedExpression::new_string(format!("{user_id}@example.com")));
    attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    attrs.insert("org".into(), RestrictedExpression::new_string("acme".into()));
    attrs.insert("subscription_tier".into(), RestrictedExpression::new_string("enterprise".into()));
    attrs.insert("suspended".into(), RestrictedExpression::new_bool(false));
    attrs.insert(
        "allowed_scopes".into(),
        RestrictedExpression::new_set(vec![RestrictedExpression::new_string("internal".into())]),
    );

    let user_entity = Entity::new(user_uid, attrs, parents).expect("valid user");

    let resource_uid = make_uid("ApiGateway::ApiResource", "/api/v1/data");
    let mut resource_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    resource_attrs.insert("service".into(), RestrictedExpression::new_string("user-service".into()));
    resource_attrs.insert("path_pattern".into(), RestrictedExpression::new_string("/api/v1/data".into()));
    resource_attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    resource_attrs.insert("classification".into(), RestrictedExpression::new_string("internal".into()));
    resource_attrs.insert("owner_org".into(), RestrictedExpression::new_string("acme".into()));
    let resource_entity = Entity::new(resource_uid, resource_attrs, HashSet::new()).expect("valid resource");

    let entities = Entities::from_entities(
        vec![admin_entity, org_entity, user_entity, resource_entity],
        Some(schema),
    )
    .expect("valid entities");

    let request = Request::new(
        make_uid("ApiGateway::User", &user_id),
        make_uid("ApiGateway::Action", "read"),
        make_uid("ApiGateway::ApiResource", "/api/v1/data"),
        Context::empty(),
        None,
    )
    .expect("valid request");

    (entities, request)
}

fn bench_rayon_crossover(c: &mut Criterion) {
    let mut group = c.benchmark_group("rayon_crossover");
    let schema = prod_schema();
    let policies = prod_policies();

    // Test batch sizes 1 through 10 to find the exact crossover point.
    for batch_size in 1..=10usize {
        let scenarios: Vec<_> = (0..batch_size)
            .map(|i| build_scenario(i, &schema))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Sequential evaluation
        group.bench_function(BenchmarkId::new("sequential", batch_size), |b| {
            let authorizer = Authorizer::new();
            b.iter(|| {
                scenarios
                    .iter()
                    .map(|(entities, request)| authorizer.is_authorized(request, &policies, entities))
                    .collect::<Vec<_>>()
            });
        });

        // Rayon parallel evaluation
        group.bench_function(BenchmarkId::new("rayon", batch_size), |b| {
            b.iter(|| {
                scenarios
                    .par_iter()
                    .map(|(entities, request)| {
                        let auth = Authorizer::new();
                        auth.is_authorized(request, &policies, entities)
                    })
                    .collect::<Vec<_>>()
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_rayon_crossover);
criterion_main!(benches);
