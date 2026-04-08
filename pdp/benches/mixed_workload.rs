//! Mixed workload benchmarks -- measures realistic heterogeneous traffic.
//!
//! All existing batch benchmarks use homogeneous admin requests. Real agent
//! traffic is a mix of roles, actions, and decision outcomes. This benchmark
//! measures:
//!   1. Heterogeneous batch throughput (mix of allow/deny/forbid decisions)
//!   2. Forbid policy overhead (same request with vs without forbid in set)
//!   3. Feature entity tier gating evaluation cost
//!
//! These answer the question a senior eng lead actually asks:
//! "What's our p50/p99 under realistic traffic, not just best-case?"

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

fn all_policies() -> PolicySet {
    format!("{POLICY_RBAC}\n{POLICY_TIER}\n{POLICY_ORG}\n{POLICY_SUSPENDED}\n{POLICY_TEMPLATE}\n{POLICY_SCOPE}")
        .parse().expect("valid policies")
}

fn policies_without_forbid() -> PolicySet {
    format!("{POLICY_RBAC}\n{POLICY_TIER}\n{POLICY_ORG}\n{POLICY_TEMPLATE}\n{POLICY_SCOPE}")
        .parse().expect("valid policies")
}

fn make_user_entity(
    id: &str,
    roles: &[&str],
    org: &str,
    tier: &str,
    suspended: bool,
    scopes: &[&str],
    schema: &Schema,
) -> (Entities, EntityUid) {
    let mut entities_vec = Vec::new();
    let mut parents = HashSet::new();

    for role in roles {
        let uid = make_uid("ApiGateway::Role", role);
        parents.insert(uid.clone());
        entities_vec.push(Entity::new_no_attrs(uid, HashSet::new()));
    }

    let org_uid = make_uid("ApiGateway::Organization", org);
    parents.insert(org_uid.clone());
    entities_vec.push(Entity::new_no_attrs(org_uid, HashSet::new()));

    let user_uid = make_uid("ApiGateway::User", id);
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert("email".into(), RestrictedExpression::new_string(format!("{id}@example.com")));
    attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    attrs.insert("org".into(), RestrictedExpression::new_string(org.into()));
    attrs.insert("subscription_tier".into(), RestrictedExpression::new_string(tier.into()));
    attrs.insert("suspended".into(), RestrictedExpression::new_bool(suspended));
    let scope_exprs: Vec<RestrictedExpression> = scopes.iter()
        .map(|s| RestrictedExpression::new_string(s.to_string()))
        .collect();
    attrs.insert("allowed_scopes".into(), RestrictedExpression::new_set(scope_exprs));

    entities_vec.push(Entity::new(user_uid.clone(), attrs, parents).unwrap());

    // Resource
    let resource_uid = make_uid("ApiGateway::ApiResource", "/api/v1/data");
    let mut resource_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    resource_attrs.insert("service".into(), RestrictedExpression::new_string("user-service".into()));
    resource_attrs.insert("path_pattern".into(), RestrictedExpression::new_string("/api/v1/data".into()));
    resource_attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    resource_attrs.insert("classification".into(), RestrictedExpression::new_string("internal".into()));
    resource_attrs.insert("owner_org".into(), RestrictedExpression::new_string(org.into()));
    entities_vec.push(Entity::new(resource_uid, resource_attrs, HashSet::new()).unwrap());

    let entities = Entities::from_entities(entities_vec, Some(schema)).unwrap();
    (entities, user_uid)
}

/// Build a realistic mixed workload: admin allows, viewer denies, suspended forbids.
/// Distribution: 60% admin reads (Allow), 25% viewer deletes (Deny), 15% suspended (Forbid).
fn build_mixed_scenarios(count: usize, schema: &Schema) -> Vec<(Entities, Request)> {
    (0..count)
        .map(|i| {
            let bucket = i % 20; // 12/20 admin, 5/20 viewer-delete, 3/20 suspended
            if bucket < 12 {
                // Admin read (Allow)
                let (entities, user_uid) = make_user_entity(
                    &format!("admin-{i}"), &["admin"], "acme", "enterprise", false, &["internal"], schema,
                );
                let request = Request::new(
                    user_uid, make_uid("ApiGateway::Action", "read"),
                    make_uid("ApiGateway::ApiResource", "/api/v1/data"),
                    Context::empty(), None,
                ).unwrap();
                (entities, request)
            } else if bucket < 17 {
                // Viewer delete (Deny -- no permit)
                let (entities, user_uid) = make_user_entity(
                    &format!("viewer-{i}"), &["viewer"], "acme", "basic", false, &["public"], schema,
                );
                let request = Request::new(
                    user_uid, make_uid("ApiGateway::Action", "delete"),
                    make_uid("ApiGateway::ApiResource", "/api/v1/data"),
                    Context::empty(), None,
                ).unwrap();
                (entities, request)
            } else {
                // Suspended admin (Forbid override)
                let (entities, user_uid) = make_user_entity(
                    &format!("suspended-{i}"), &["admin"], "acme", "enterprise", true, &["internal"], schema,
                );
                let request = Request::new(
                    user_uid, make_uid("ApiGateway::Action", "read"),
                    make_uid("ApiGateway::ApiResource", "/api/v1/data"),
                    Context::empty(), None,
                ).unwrap();
                (entities, request)
            }
        })
        .collect()
}

// ===========================================================================
// Mixed workload batch throughput
// ===========================================================================

fn bench_mixed_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_workload_batch");
    let schema = prod_schema();
    let policies = all_policies();

    for batch_size in [10usize, 25, 50, 100] {
        let scenarios = build_mixed_scenarios(batch_size, &schema);

        group.throughput(Throughput::Elements(batch_size as u64));

        // Sequential
        group.bench_function(BenchmarkId::new("sequential", batch_size), |b| {
            let authorizer = Authorizer::new();
            b.iter(|| {
                scenarios.iter()
                    .map(|(entities, request)| authorizer.is_authorized(request, &policies, entities))
                    .collect::<Vec<_>>()
            });
        });

        // Rayon parallel
        group.bench_function(BenchmarkId::new("rayon", batch_size), |b| {
            b.iter(|| {
                scenarios.par_iter()
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

// ===========================================================================
// Forbid overhead: same request with vs without suspended_account_deny.cedar
// ===========================================================================

fn bench_forbid_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("forbid_overhead");
    let schema = prod_schema();
    let with_forbid = all_policies();
    let without_forbid = policies_without_forbid();
    let authorizer = Authorizer::new();

    // Active admin read (suspended=false). The forbid policy evaluates but
    // doesn't fire. Does it add measurable overhead?
    let (entities, user_uid) = make_user_entity(
        "forbid-bench", &["admin"], "acme", "enterprise", false, &["internal"], &schema,
    );
    let request = Request::new(
        user_uid,
        make_uid("ApiGateway::Action", "read"),
        make_uid("ApiGateway::ApiResource", "/api/v1/data"),
        Context::empty(),
        None,
    ).unwrap();

    group.bench_function("without_forbid_policy", |b| {
        b.iter(|| authorizer.is_authorized(&request, &without_forbid, &entities));
    });

    group.bench_function("with_forbid_policy_not_firing", |b| {
        b.iter(|| authorizer.is_authorized(&request, &with_forbid, &entities));
    });

    // Same request but suspended=true -- forbid fires and overrides permits
    let (suspended_entities, suspended_uid) = make_user_entity(
        "forbid-bench-sus", &["admin"], "acme", "enterprise", true, &["internal"], &schema,
    );
    let suspended_request = Request::new(
        suspended_uid,
        make_uid("ApiGateway::Action", "read"),
        make_uid("ApiGateway::ApiResource", "/api/v1/data"),
        Context::empty(),
        None,
    ).unwrap();

    group.bench_function("with_forbid_policy_firing", |b| {
        b.iter(|| authorizer.is_authorized(&suspended_request, &with_forbid, &suspended_entities));
    });

    group.finish();
}

// ===========================================================================
// Feature entity tier gating evaluation cost
// ===========================================================================

fn bench_tier_gating(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier_gating");
    let schema = prod_schema();
    let policies = all_policies();
    let authorizer = Authorizer::new();

    // Build Feature entities for tier gating
    let tiers = [
        ("enterprise-user", "enterprise", "ent-feature", "enterprise"),
        ("professional-user", "professional", "pro-feature", "professional"),
        ("basic-user", "basic", "basic-feature", "basic"),
        ("pro-denied", "professional", "ent-feature", "enterprise"),  // deny case
    ];

    for (user_id, user_tier, feature_id, feature_tier) in &tiers {
        let org_uid = make_uid("ApiGateway::Organization", "acme");
        let org_entity = Entity::new_no_attrs(org_uid.clone(), HashSet::new());

        let user_uid = make_uid("ApiGateway::User", user_id);
        let mut user_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        user_attrs.insert("email".into(), RestrictedExpression::new_string(format!("{user_id}@test.com")));
        user_attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
        user_attrs.insert("org".into(), RestrictedExpression::new_string("acme".into()));
        user_attrs.insert("subscription_tier".into(), RestrictedExpression::new_string(user_tier.to_string()));
        user_attrs.insert("suspended".into(), RestrictedExpression::new_bool(false));
        user_attrs.insert("allowed_scopes".into(), RestrictedExpression::new_set(vec![]));
        let mut parents = HashSet::new();
        parents.insert(org_uid);
        let user_entity = Entity::new(user_uid, user_attrs, parents).unwrap();

        let feature_uid = make_uid("ApiGateway::Feature", feature_id);
        let mut feat_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        feat_attrs.insert("required_tier".into(), RestrictedExpression::new_string(feature_tier.to_string()));
        let feature_entity = Entity::new(feature_uid, feat_attrs, HashSet::new()).unwrap();

        let entities = Entities::from_entities(
            vec![user_entity, org_entity, feature_entity],
            Some(&schema),
        ).unwrap();

        let request = Request::new(
            make_uid("ApiGateway::User", user_id),
            make_uid("ApiGateway::Action", "read"),
            make_uid("ApiGateway::Feature", feature_id),
            Context::empty(),
            Some(&schema),
        ).unwrap();

        let label = format!("{user_tier}_reads_{feature_tier}");
        group.bench_function(&label, |b| {
            b.iter(|| authorizer.is_authorized(&request, &policies, &entities));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_mixed_batch, bench_forbid_overhead, bench_tier_gating);
criterion_main!(benches);
