//! Batch throughput benchmarks -- measures rayon parallel evaluation scaling.
//!
//! Validates AGI-Acc F2: batch evaluation at agent-scale workloads.
//! Measures throughput at various batch sizes to quantify rayon speedup
//! over sequential evaluation and identify the concurrency sweet spot.

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
    Schema::from_cedarschema_str(PROD_SCHEMA)
        .expect("valid schema")
        .0
}

fn prod_policies() -> PolicySet {
    let combined = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        POLICY_RBAC, POLICY_TIER, POLICY_ORG, POLICY_SUSPENDED, POLICY_TEMPLATE, POLICY_SCOPE
    );
    combined.parse::<PolicySet>().expect("valid policies")
}

/// Build a complete entity set + request for a single authorization check.
/// Each call produces a unique user ID to avoid entity deduplication.
fn build_scenario(user_idx: usize, schema: &Schema) -> (Entities, Request) {
    let user_id = format!("bench-user-{user_idx}");

    // Role entity
    let admin_uid = make_uid("ApiGateway::Role", "admin");
    let admin_entity = Entity::new_no_attrs(admin_uid.clone(), HashSet::new());

    // Org entity
    let org_uid = make_uid("ApiGateway::Organization", "acme");
    let org_entity = Entity::new_no_attrs(org_uid.clone(), HashSet::new());

    // User entity with attributes
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

    // Resource entity
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

    let principal = make_uid("ApiGateway::User", &user_id);
    let action = make_uid("ApiGateway::Action", "read");
    let resource = make_uid("ApiGateway::ApiResource", "/api/v1/data");
    let request = Request::new(principal, action, resource, Context::empty(), None)
        .expect("valid request");

    (entities, request)
}

fn bench_batch_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_sequential");
    let schema = prod_schema();
    let policies = prod_policies();
    let authorizer = Authorizer::new();

    for batch_size in [1usize, 5, 10, 25, 50, 100] {
        let scenarios: Vec<_> = (0..batch_size)
            .map(|i| build_scenario(i, &schema))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(BenchmarkId::new("size", batch_size), |b| {
            b.iter(|| {
                let mut results = Vec::with_capacity(batch_size);
                for (entities, request) in &scenarios {
                    results.push(authorizer.is_authorized(request, &policies, entities));
                }
                results
            });
        });
    }
    group.finish();
}

fn bench_batch_rayon(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_rayon");
    let schema = prod_schema();
    let policies = prod_policies();

    for batch_size in [1usize, 5, 10, 25, 50, 100] {
        let scenarios: Vec<_> = (0..batch_size)
            .map(|i| build_scenario(i, &schema))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(BenchmarkId::new("size", batch_size), |b| {
            b.iter(|| {
                scenarios
                    .par_iter()
                    .map(|(entities, request)| {
                        let authorizer = Authorizer::new();
                        authorizer.is_authorized(request, &policies, entities)
                    })
                    .collect::<Vec<_>>()
            });
        });
    }
    group.finish();
}

/// Measures speedup factor: sequential time / rayon time at batch_size=100.
/// This isn't a Criterion benchmark per se -- it runs a fixed iteration count
/// and reports the ratio. Useful for regression detection.
fn bench_rayon_speedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("rayon_speedup_100");
    let schema = prod_schema();
    let policies = prod_policies();
    let authorizer = Authorizer::new();
    let batch_size = 100;
    let scenarios: Vec<_> = (0..batch_size)
        .map(|i| build_scenario(i, &schema))
        .collect();

    group.throughput(Throughput::Elements(batch_size as u64));

    group.bench_function("sequential", |b| {
        b.iter(|| {
            scenarios
                .iter()
                .map(|(entities, request)| authorizer.is_authorized(request, &policies, entities))
                .collect::<Vec<_>>()
        });
    });

    group.bench_function("rayon", |b| {
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

    group.finish();
}

criterion_group!(benches, bench_batch_sequential, bench_batch_rayon, bench_rayon_speedup);
criterion_main!(benches);
