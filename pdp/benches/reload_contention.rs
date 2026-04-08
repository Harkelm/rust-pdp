//! Reload contention benchmark -- measures Cedar evaluation latency
//! while concurrent policy reloads are in flight.
//!
//! Addresses AGI-Acc F3: does arc-swap reload degrade eval performance?
//! The expected answer is "no" (arc-swap is lock-free), but this benchmark
//! provides the evidence.

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request,
    RestrictedExpression, Schema,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

fn build_test_entities(schema: &Schema) -> Entities {
    let admin_uid = make_uid("ApiGateway::Role", "admin");
    let org_uid = make_uid("ApiGateway::Organization", "acme");
    let user_uid = make_uid("ApiGateway::User", "bench-user");
    let resource_uid = make_uid("ApiGateway::ApiResource", "/api/v1/data");

    let mut user_parents = HashSet::new();
    user_parents.insert(admin_uid.clone());
    user_parents.insert(org_uid.clone());

    let mut user_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    user_attrs.insert("email".into(), RestrictedExpression::new_string("b@example.com".into()));
    user_attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    user_attrs.insert("org".into(), RestrictedExpression::new_string("acme".into()));
    user_attrs.insert("subscription_tier".into(), RestrictedExpression::new_string("enterprise".into()));
    user_attrs.insert("suspended".into(), RestrictedExpression::new_bool(false));
    user_attrs.insert(
        "allowed_scopes".into(),
        RestrictedExpression::new_set(vec![RestrictedExpression::new_string("internal".into())]),
    );

    let mut resource_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    resource_attrs.insert("service".into(), RestrictedExpression::new_string("user-service".into()));
    resource_attrs.insert("path_pattern".into(), RestrictedExpression::new_string("/api/v1/data".into()));
    resource_attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    resource_attrs.insert("classification".into(), RestrictedExpression::new_string("internal".into()));
    resource_attrs.insert("owner_org".into(), RestrictedExpression::new_string("acme".into()));

    Entities::from_entities(
        vec![
            Entity::new_no_attrs(admin_uid, HashSet::new()),
            Entity::new_no_attrs(org_uid, HashSet::new()),
            Entity::new(user_uid, user_attrs, user_parents).unwrap(),
            Entity::new(resource_uid, resource_attrs, HashSet::new()).unwrap(),
        ],
        Some(schema),
    )
    .unwrap()
}

fn bench_eval_no_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("reload_contention");

    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = Arc::new(
        cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies"),
    );

    let state = store.load();
    let (policies, schema) = state.as_ref();
    let entities = build_test_entities(schema);
    let request = Request::new(
        make_uid("ApiGateway::User", "bench-user"),
        make_uid("ApiGateway::Action", "read"),
        make_uid("ApiGateway::ApiResource", "/api/v1/data"),
        Context::empty(),
        None,
    )
    .unwrap();
    let authorizer = Authorizer::new();

    // Baseline: eval with no concurrent reloads
    group.bench_function("eval_baseline", |b| {
        b.iter(|| authorizer.is_authorized(&request, policies, &entities));
    });

    // Eval while a background thread continuously reloads
    let reload_store = Arc::clone(&store);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let reload_thread = thread::spawn(move || {
        let mut count = 0u64;
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = reload_store.reload();
            count += 1;
        }
        count
    });

    // Re-load state through the store (arc-swap path) during contention
    group.bench_function("eval_during_reload", |b| {
        b.iter(|| {
            let state = store.load();
            let (ps, _schema) = state.as_ref();
            authorizer.is_authorized(&request, ps, &entities)
        });
    });

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let reload_count = reload_thread.join().unwrap();
    eprintln!("Background reloads during benchmark: {reload_count}");

    group.finish();
}

criterion_group!(benches, bench_eval_no_contention);
criterion_main!(benches);
