//! Benchmarks measuring the overhead of AVP-format request parsing vs native format.
//!
//! Quantifies the cost of API compatibility: how much does it cost to accept
//! AVP-style JSON (typed value wrappers, structured entity identifiers) and
//! translate it into Cedar SDK types, compared to the existing native format?

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use cedar_pdp::avp;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

// -- Production schema and policies ----------------------------------------

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

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

// -- Native format (current rust-pdp) -------------------------------------

/// Simulates the current native format parsing path: Cedar UID strings + claims.
fn native_format_request() -> Value {
    serde_json::json!({
        "principal": "ApiGateway::User::\"alice\"",
        "action": "ApiGateway::Action::\"read\"",
        "resource": "ApiGateway::ApiResource::\"/api/v1/users\"",
        "context": {},
        "claims": {
            "sub": "alice",
            "email": "alice@example.com",
            "org": "acme",
            "roles": ["admin"],
            "department": "engineering",
            "subscription_tier": "enterprise",
            "suspended": false,
            "allowed_scopes": ["internal"]
        }
    })
}

/// Parse native format into Cedar types (mirrors handlers.rs evaluate_single_inner).
fn parse_native(json: &Value, schema: &Schema) -> (EntityUid, EntityUid, EntityUid, Entities, Context) {
    let claims = json.get("claims").unwrap();

    let sub = claims["sub"].as_str().unwrap();
    let principal = make_uid("ApiGateway::User", sub);
    let action = make_uid("ApiGateway::Action", "read");
    let resource = make_uid("ApiGateway::ApiResource", "/api/v1/users");

    // Build entities from claims (simplified version of entities.rs build_entities)
    let mut entities_vec = Vec::new();

    // User entity
    let email = claims["email"].as_str().unwrap();
    let org = claims["org"].as_str().unwrap();
    let dept = claims["department"].as_str().unwrap();
    let tier = claims["subscription_tier"].as_str().unwrap();
    let suspended = claims["suspended"].as_bool().unwrap();
    let scopes: Vec<RestrictedExpression> = claims["allowed_scopes"]
        .as_array().unwrap()
        .iter()
        .map(|v| RestrictedExpression::new_string(v.as_str().unwrap().to_string()))
        .collect();

    let mut parents = HashSet::new();
    for role in claims["roles"].as_array().unwrap() {
        let role_uid = make_uid("ApiGateway::Role", role.as_str().unwrap());
        parents.insert(role_uid.clone());
        entities_vec.push(Entity::new_no_attrs(role_uid, HashSet::new()));
    }
    let org_uid = make_uid("ApiGateway::Organization", org);
    parents.insert(org_uid.clone());
    entities_vec.push(Entity::new_no_attrs(org_uid, HashSet::new()));

    let mut attrs = HashMap::new();
    attrs.insert("email".into(), RestrictedExpression::new_string(email.into()));
    attrs.insert("department".into(), RestrictedExpression::new_string(dept.into()));
    attrs.insert("org".into(), RestrictedExpression::new_string(org.into()));
    attrs.insert("subscription_tier".into(), RestrictedExpression::new_string(tier.into()));
    attrs.insert("suspended".into(), RestrictedExpression::new_bool(suspended));
    attrs.insert("allowed_scopes".into(), RestrictedExpression::new_set(scopes));

    let user = Entity::new(principal.clone(), attrs, parents).expect("valid user entity");
    entities_vec.push(user);

    // Resource entity
    let mut res_attrs = HashMap::new();
    res_attrs.insert("service".into(), RestrictedExpression::new_string("user-service".into()));
    res_attrs.insert("path_pattern".into(), RestrictedExpression::new_string("/api/v1/users".into()));
    res_attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    res_attrs.insert("classification".into(), RestrictedExpression::new_string("internal".into()));
    res_attrs.insert("owner_org".into(), RestrictedExpression::new_string("acme".into()));
    let res_entity = Entity::new(resource.clone(), res_attrs, HashSet::new()).expect("valid resource");
    entities_vec.push(res_entity);

    let entities = Entities::from_entities(entities_vec, Some(schema)).expect("valid entities");
    let context = Context::empty();

    (principal, action, resource, entities, context)
}

// -- AVP format -----------------------------------------------------------

/// AVP-format request with typed value wrappers and structured entity identifiers.
fn avp_format_request() -> Value {
    serde_json::json!({
        "policyStoreId": "PSexample123",
        "principal": {
            "entityType": "ApiGateway::User",
            "entityId": "alice"
        },
        "action": {
            "actionType": "ApiGateway::Action",
            "actionId": "read"
        },
        "resource": {
            "entityType": "ApiGateway::ApiResource",
            "entityId": "/api/v1/users"
        },
        "context": {
            "contextMap": {}
        },
        "entities": {
            "entityList": [
                {
                    "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                    "Attributes": {
                        "email": { "String": "alice@example.com" },
                        "department": { "String": "engineering" },
                        "org": { "String": "acme" },
                        "subscription_tier": { "String": "enterprise" },
                        "suspended": { "Boolean": false },
                        "allowed_scopes": { "Set": [{ "String": "internal" }] }
                    },
                    "Parents": [
                        { "EntityType": "ApiGateway::Role", "EntityId": "admin" },
                        { "EntityType": "ApiGateway::Organization", "EntityId": "acme" }
                    ]
                },
                {
                    "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" },
                    "Attributes": {},
                    "Parents": []
                },
                {
                    "Identifier": { "EntityType": "ApiGateway::Organization", "EntityId": "acme" },
                    "Attributes": {},
                    "Parents": []
                },
                {
                    "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/api/v1/users" },
                    "Attributes": {
                        "service": { "String": "user-service" },
                        "path_pattern": { "String": "/api/v1/users" },
                        "department": { "String": "engineering" },
                        "classification": { "String": "internal" },
                        "owner_org": { "String": "acme" }
                    },
                    "Parents": []
                }
            ]
        }
    })
}

/// Parse AVP-format JSON into Cedar types using the library's avp module.
fn parse_avp(json: &Value, schema: &Schema) -> (EntityUid, EntityUid, EntityUid, Entities, Context) {
    let req: avp::AvpIsAuthorizedRequest = serde_json::from_value(json.clone()).unwrap();

    let principal = avp::entity_ref_to_uid(&req.principal).unwrap();
    let action = avp::action_ref_to_uid(&req.action).unwrap();
    let resource = avp::entity_ref_to_uid(&req.resource).unwrap();
    let entities = avp::build_cedar_entities(&req.entities, Some(schema)).unwrap();
    let context = avp::build_cedar_context(&req.context).unwrap();

    (principal, action, resource, entities, context)
}

// -- Benchmarks -----------------------------------------------------------

fn bench_format_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("avp_format_overhead");
    let schema = prod_schema();

    let native_json = native_format_request();
    let avp_json = avp_format_request();

    // Benchmark 1: Parse-only (no Cedar evaluation)
    group.bench_function("parse_native_format", |b| {
        b.iter(|| parse_native(&native_json, &schema));
    });

    group.bench_function("parse_avp_format", |b| {
        b.iter(|| parse_avp(&avp_json, &schema));
    });

    // Benchmark 2: Parse + evaluate (full path)
    let policy_set = prod_policy_set();
    let authorizer = Authorizer::new();

    group.bench_function("full_path_native", |b| {
        b.iter(|| {
            let (principal, action, resource, entities, context) =
                parse_native(&native_json, &schema);
            let request =
                Request::new(principal, action, resource, context, Some(&schema)).unwrap();
            authorizer.is_authorized(&request, &policy_set, &entities)
        });
    });

    group.bench_function("full_path_avp", |b| {
        b.iter(|| {
            let (principal, action, resource, entities, context) =
                parse_avp(&avp_json, &schema);
            let request =
                Request::new(principal, action, resource, context, Some(&schema)).unwrap();
            authorizer.is_authorized(&request, &policy_set, &entities)
        });
    });

    group.finish();
}

fn bench_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("avp_response_format");

    // Benchmark response serialization: native vs AVP format
    let native_response = serde_json::json!({
        "decision": "Allow",
        "diagnostics": {
            "reason": ["rbac_route_access"],
            "errors": []
        }
    });

    let avp_response = serde_json::json!({
        "decision": "ALLOW",
        "determiningPolicies": [
            { "policyId": "rbac_route_access" }
        ],
        "errors": []
    });

    group.bench_function("serialize_native_response", |b| {
        b.iter(|| serde_json::to_vec(&native_response).unwrap());
    });

    group.bench_function("serialize_avp_response", |b| {
        b.iter(|| serde_json::to_vec(&avp_response).unwrap());
    });

    group.finish();
}

fn bench_batch_format(c: &mut Criterion) {
    let mut group = c.benchmark_group("avp_batch_overhead");
    let schema = prod_schema();
    let policy_set = prod_policy_set();
    let authorizer = Authorizer::new();

    // Compare batch sizes: AVP max (30) vs native max (100)
    for batch_size in [10, 30, 100] {
        let native_requests: Vec<Value> = (0..batch_size)
            .map(|_| native_format_request())
            .collect();
        let avp_requests: Vec<Value> = (0..batch_size)
            .map(|_| avp_format_request())
            .collect();

        if batch_size <= 30 {
            group.bench_function(
                BenchmarkId::new("batch_avp", batch_size),
                |b| {
                    b.iter(|| {
                        for req in &avp_requests {
                            let (principal, action, resource, entities, context) =
                                parse_avp(req, &schema);
                            let request = Request::new(
                                principal, action, resource, context, Some(&schema),
                            )
                            .unwrap();
                            authorizer.is_authorized(&request, &policy_set, &entities);
                        }
                    });
                },
            );
        }

        group.bench_function(
            BenchmarkId::new("batch_native", batch_size),
            |b| {
                b.iter(|| {
                    for req in &native_requests {
                        let (principal, action, resource, entities, context) =
                            parse_native(req, &schema);
                        let request = Request::new(
                            principal, action, resource, context, Some(&schema),
                        )
                        .unwrap();
                        authorizer.is_authorized(&request, &policy_set, &entities);
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_format_parsing, bench_json_serialization, bench_batch_format);
criterion_main!(benches);
