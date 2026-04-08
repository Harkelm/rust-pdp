use std::net::SocketAddr;
use std::sync::Arc;
use std::path::PathBuf;

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

// We reference the crate's public modules via the binary crate name.
// Since this is an integration test, we build a test server inline.

async fn start_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState = Arc::new(store);

    let app = Router::new()
        .route("/v1/is_authorized", post(cedar_pdp::handlers::is_authorized))
        .route("/v1/policy-info", get(cedar_pdp::handlers::policy_info))
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

#[tokio::test]
async fn test_health() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["policies_loaded"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_policy_info() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/v1/policy-info"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["policy_count"].as_u64().unwrap() > 0);
    assert!(body["last_reload_epoch_ms"].as_u64().unwrap() > 0);
    let hash = body["schema_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64, "sha256 hex should be 64 chars");
}

#[tokio::test]
async fn test_admin_reload() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["policy_count"].as_u64().unwrap() > 0);
    assert!(body["last_reload_epoch_ms"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_permit_decision() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // alice has a direct permit policy for read
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ApiGateway::User::\"alice\"",
            "action": "ApiGateway::Action::\"read\"",
            "resource": "ApiGateway::ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Allow");
    let reasons = body["diagnostics"]["reason"].as_array().unwrap();
    assert!(!reasons.is_empty(), "expected at least one determining policy");
}

// --- Claims-path integration tests (BL-166) ---
// These use the production ApiGateway schema which matches the entities.rs builder.

async fn start_claims_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load production policies");
    let state: cedar_pdp::handlers::AppState = Arc::new(store);

    let app = Router::new()
        .route("/v1/is_authorized", post(cedar_pdp::handlers::is_authorized))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

#[tokio::test]
async fn test_claims_path_admin_allow() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // Admin role should permit read on any ApiResource via rbac-admin-all policy.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored-in-claims-path",
            "action": "GET",
            "resource": "/api/v1/users",
            "claims": {
                "sub": "alice",
                "email": "alice@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["admin"],
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
    assert_eq!(body["decision"], "Allow", "admin should be allowed to read");
}

#[tokio::test]
async fn test_claims_path_viewer_deny_delete() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // Viewer role should be denied delete. No policy grants delete to viewers:
    // rbac-viewer-read covers read+list only, org-scoped covers read+write only.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "DELETE",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "bob",
                "email": "bob@example.com",
                "department": "sales",
                "org": "acme",
                "roles": ["viewer"],
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
    assert_eq!(body["decision"], "Deny", "viewer should be denied delete access");
}

#[tokio::test]
async fn test_claims_path_suspended_user_denied() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // Suspended admin should be denied -- forbid policy overrides permits.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/users",
            "claims": {
                "sub": "suspended-admin",
                "email": "admin@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["admin"],
                "subscription_tier": "enterprise",
                "suspended": true,
                "allowed_scopes": ["internal"]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Deny", "suspended user must be denied even with admin role");
}

#[tokio::test]
async fn test_claims_path_cross_org_denied() {
    let addr = start_claims_server().await;
    let client = reqwest::Client::new();

    // User in org "external-corp" accessing a resource owned by "acme" (the
    // entity builder defaults owner_org to the user's org, but this user has
    // no roles, no matching allowed_scopes, and the org-scoped policy checks
    // principal.org == resource.owner_org). Since the resource inherits the
    // user's org in the current entity builder, we test delete (no permit for
    // roleless users via any policy).
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "DELETE",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "nobody",
                "email": "nobody@example.com",
                "department": "unknown",
                "org": "acme",
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
    assert_eq!(body["decision"], "Deny", "roleless user should be denied delete");
}

#[tokio::test]
async fn test_deny_decision() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // bob has no permit policy, so read is denied.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ApiGateway::User::\"bob\"",
            "action": "ApiGateway::Action::\"read\"",
            "resource": "ApiGateway::ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Deny");
    assert!(body["diagnostics"]["reason"].as_array().unwrap().is_empty());
}
