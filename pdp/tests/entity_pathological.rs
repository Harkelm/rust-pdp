//! Pathological entity construction tests.
//!
//! Verifies that entity construction handles extreme role and scope counts
//! without panicking and that authorization decisions remain correct when a
//! user has an unusually large number of roles or scopes. These are edge cases
//! that could surface in production when JWT claims contain aggregated roles
//! from many identity providers or nested group memberships.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

use cedar_pdp::entities::{build_entities, Claims, RequestContext};
use cedar_pdp::policy::PolicyStore;

use common::production_policy_dir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load the production schema for unit tests that call build_entities directly.
fn production_schema() -> cedar_policy::Schema {
    let policy_dir = production_policy_dir();
    let store = PolicyStore::from_dir(&policy_dir).expect("load production policies");
    let state = store.load();
    let (_, schema) = state.as_ref();
    schema.clone()
}

fn make_claims_with_n_roles(n: usize) -> Claims {
    let roles: Vec<String> = (0..n).map(|i| format!("role-{i}")).collect();
    Claims {
        sub: "test-user".to_string(),
        email: Some("test@example.com".to_string()),
        department: Some("engineering".to_string()),
        org: Some("acme".to_string()),
        roles: Some(roles),
        subscription_tier: Some("enterprise".to_string()),
        suspended: Some(false),
        allowed_scopes: Some(vec!["internal".to_string()]),
    }
}

fn default_request_ctx() -> RequestContext {
    RequestContext {
        method: "GET".to_string(),
        path: "/api/v1/data".to_string(),
        service: None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests: entity construction with many roles
// ---------------------------------------------------------------------------

/// Build entities from claims with 100 roles. Verify all 100 role entities
/// are created and the user entity has all 100 as parents.
#[test]
fn test_entity_construction_100_roles() {
    let schema = production_schema();
    let claims = make_claims_with_n_roles(100);
    let ctx = default_request_ctx();

    let entities = build_entities(&claims, &ctx, Some(&schema))
        .expect("100-role entity construction must not panic");

    // Verify all 100 role entities exist.
    for i in 0..100 {
        let role_name = format!("role-{i}");
        let role_uid = cedar_policy::EntityUid::from_type_name_and_id(
            "ApiGateway::Role".parse().unwrap(),
            cedar_policy::EntityId::new(&role_name),
        );
        assert!(
            entities.get(&role_uid).is_some(),
            "role entity for {role_name} must be present"
        );
    }

    // Verify the user entity exists and has all roles as ancestors.
    let user_uid = cedar_policy::EntityUid::from_type_name_and_id(
        "ApiGateway::User".parse().unwrap(),
        cedar_policy::EntityId::new("test-user"),
    );
    assert!(entities.get(&user_uid).is_some(), "user entity must exist");

    for i in 0..100 {
        let role_uid = cedar_policy::EntityUid::from_type_name_and_id(
            "ApiGateway::Role".parse().unwrap(),
            cedar_policy::EntityId::new(format!("role-{i}")),
        );
        assert!(
            entities.is_ancestor_of(&role_uid, &user_uid),
            "role-{i} must be an ancestor of the user"
        );
    }
}

/// Build entities from claims with 500 roles. Verify construction succeeds
/// without panicking or returning an error.
#[test]
fn test_entity_construction_500_roles() {
    let schema = production_schema();
    let claims = make_claims_with_n_roles(500);
    let ctx = default_request_ctx();

    let entities = build_entities(&claims, &ctx, Some(&schema))
        .expect("500-role entity construction must succeed without panic");

    // Spot check: user + 500 roles + 1 org + 1 resource = 503
    let user_uid = cedar_policy::EntityUid::from_type_name_and_id(
        "ApiGateway::User".parse().unwrap(),
        cedar_policy::EntityId::new("test-user"),
    );
    assert!(entities.get(&user_uid).is_some(), "user entity must exist");

    // Verify a sample of role entities.
    for i in [0, 99, 250, 499] {
        let role_uid = cedar_policy::EntityUid::from_type_name_and_id(
            "ApiGateway::Role".parse().unwrap(),
            cedar_policy::EntityId::new(format!("role-{i}")),
        );
        assert!(
            entities.get(&role_uid).is_some(),
            "role-{i} must be present in 500-role set"
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP tests: many roles still produce correct authorization decisions
// ---------------------------------------------------------------------------

/// Start a claims-path server using production policies (../policies/).
async fn start_claims_server() -> SocketAddr {
    let policy_dir = production_policy_dir();
    let store = PolicyStore::from_dir(&policy_dir).expect("load production policies");
    let state: cedar_pdp::handlers::AppState =
        Arc::new(cedar_pdp::handlers::AppContext::new(store, None));

    let app = Router::new()
        .route(
            "/v1/is_authorized",
            post(cedar_pdp::handlers::is_authorized),
        )
        .route(
            "/v1/batch_is_authorized",
            post(cedar_pdp::handlers::batch_is_authorized),
        )
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// User with 100 roles including "admin" should still get Allow on
/// admin-permitted routes. The admin role must not be drowned out by the
/// 99 filler roles.
#[tokio::test]
async fn test_claims_path_many_roles_still_allows() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // Build 99 filler roles + "admin"
    let mut roles: Vec<String> = (0..99).map(|i| format!("filler-role-{i}")).collect();
    roles.push("admin".to_string());

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/users",
            "claims": {
                "sub": "many-role-admin",
                "email": "admin@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": roles,
                "subscription_tier": "enterprise",
                "suspended": false,
                "allowed_scopes": ["internal"]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Allow",
        "admin role among 100 roles must still produce Allow"
    );
}

/// User with 100 allowed_scopes should still get correct authorization
/// decisions. The scopes set should not cause parsing or evaluation failures.
#[tokio::test]
async fn test_claims_path_many_scopes_still_allows() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // Build 99 filler scopes + "internal"
    let mut scopes: Vec<String> = (0..99).map(|i| format!("filler-scope-{i}")).collect();
    scopes.push("internal".to_string());

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/users",
            "claims": {
                "sub": "many-scope-admin",
                "email": "admin@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["admin"],
                "subscription_tier": "enterprise",
                "suspended": false,
                "allowed_scopes": scopes
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Allow",
        "admin with 100 scopes must still be allowed"
    );
}

/// Verify that a user with many roles but NOT admin is correctly denied
/// admin-only operations. This is the negative test: many roles should not
/// accidentally grant access.
#[tokio::test]
async fn test_claims_path_many_roles_without_admin_denied() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // 100 filler roles, none of which is "admin" or "viewer"
    let roles: Vec<String> = (0..100).map(|i| format!("custom-role-{i}")).collect();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "DELETE",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "no-admin-user",
                "email": "noone@example.com",
                "department": "sales",
                "org": "acme",
                "roles": roles,
                "subscription_tier": "basic",
                "suspended": false,
                "allowed_scopes": []
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Deny",
        "user with 100 non-admin roles must be denied delete"
    );
}
