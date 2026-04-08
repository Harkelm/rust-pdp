//! Action coverage and HTTP method mapping tests.
//!
//! Documents the relationship between HTTP methods, Cedar actions, and
//! RBAC policy grants. Identifies which schema-defined actions are reachable
//! through the claims path and which are not.
//!
//! KEY FINDING: The schema defines 5 actions (read, write, delete, list, admin)
//! and RBAC policies grant them to roles. But method_to_action() only maps
//! HTTP methods to read/write/delete. The "list" and "admin" actions are
//! UNREACHABLE through the claims path -- they exist in policies but no HTTP
//! method triggers them. This means:
//!   - rbac-admin-all's grant of "admin" action is dead code via claims path
//!   - rbac-editor-rw's grant of "list" action is dead code via claims path
//!   - rbac-viewer-read's grant of "list" action is dead code via claims path
//!
//! These are reachable only via the legacy Cedar UID path where the caller
//! explicitly specifies the action UID.

use std::net::SocketAddr;
use std::sync::Arc;
use std::path::PathBuf;

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

async fn start_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState = Arc::new(store);

    let app = Router::new()
        .route("/v1/is_authorized", post(cedar_pdp::handlers::is_authorized))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn admin_claims() -> serde_json::Value {
    serde_json::json!({
        "sub": "action-admin",
        "email": "admin@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["admin"],
        "subscription_tier": "enterprise",
        "suspended": false,
        "allowed_scopes": ["internal"]
    })
}

async fn authz(addr: SocketAddr, action: &str, resource: &str, claims: serde_json::Value) -> serde_json::Value {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": action,
            "resource": resource,
            "claims": claims
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

// ===========================================================================
// HEAD and OPTIONS: mapped to "read" action
// ===========================================================================

#[tokio::test]
async fn test_head_maps_to_read_allows_admin() {
    let addr = start_server().await;
    let body = authz(addr, "HEAD", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Allow",
        "HEAD must map to 'read' action and allow admin"
    );
}

#[tokio::test]
async fn test_options_maps_to_read_allows_admin() {
    let addr = start_server().await;
    let body = authz(addr, "OPTIONS", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Allow",
        "OPTIONS must map to 'read' action and allow admin"
    );
}

#[tokio::test]
async fn test_head_viewer_allowed_via_read_mapping() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "action-viewer",
        "email": "viewer@acme.com",
        "department": "sales",
        "org": "acme",
        "roles": ["viewer"],
        "subscription_tier": "basic",
        "suspended": false,
        "allowed_scopes": ["public"]
    });
    let body = authz(addr, "HEAD", "/api/v1/data", claims).await;
    assert_eq!(
        body["decision"], "Allow",
        "HEAD maps to read -- viewer has read permission via rbac-viewer-read + org-scoped"
    );
}

// ===========================================================================
// PUT and PATCH: mapped to "write" action
// ===========================================================================

#[tokio::test]
async fn test_put_maps_to_write_allows_editor() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "action-editor",
        "email": "editor@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["editor"],
        "subscription_tier": "professional",
        "suspended": false,
        "allowed_scopes": ["internal"]
    });
    let body = authz(addr, "PUT", "/api/v1/data", claims).await;
    assert_eq!(body["decision"], "Allow", "PUT must map to write and allow editor");
}

#[tokio::test]
async fn test_patch_maps_to_write_allows_editor() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "action-editor",
        "email": "editor@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["editor"],
        "subscription_tier": "professional",
        "suspended": false,
        "allowed_scopes": ["internal"]
    });
    let body = authz(addr, "PATCH", "/api/v1/data", claims).await;
    assert_eq!(body["decision"], "Allow", "PATCH must map to write and allow editor");
}

// ===========================================================================
// Case insensitivity: method_to_action uppercases input
// ===========================================================================

#[tokio::test]
async fn test_lowercase_get_maps_to_read() {
    let addr = start_server().await;
    let body = authz(addr, "get", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Allow",
        "lowercase 'get' must be treated as GET -> read"
    );
}

#[tokio::test]
async fn test_mixed_case_post_maps_to_write() {
    let addr = start_server().await;
    let body = authz(addr, "Post", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Allow",
        "mixed case 'Post' must be treated as POST -> write"
    );
}

#[tokio::test]
async fn test_lowercase_delete_maps_to_delete() {
    let addr = start_server().await;
    let body = authz(addr, "delete", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Allow",
        "lowercase 'delete' must be treated as DELETE -> delete"
    );
}

// ===========================================================================
// Unreachable actions: "list" and "admin" exist in schema but no HTTP method
// maps to them. These are reachable only via legacy Cedar UID path.
// ===========================================================================

#[tokio::test]
async fn test_list_action_unreachable_via_claims_path() {
    let addr = start_server().await;
    // There is no HTTP method that maps to "list". Sending "LIST" as the
    // method should be treated as unknown and denied.
    let body = authz(addr, "LIST", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Deny",
        "LIST is not a valid HTTP method -- denied via fail-closed. \
         The Cedar 'list' action is unreachable through the claims path."
    );
}

#[tokio::test]
async fn test_admin_action_unreachable_via_claims_path() {
    let addr = start_server().await;
    // There is no HTTP method that maps to "admin". Sending "ADMIN" as the
    // method should be treated as unknown and denied.
    let body = authz(addr, "ADMIN", "/api/v1/data", admin_claims()).await;
    assert_eq!(
        body["decision"], "Deny",
        "ADMIN is not a valid HTTP method -- denied via fail-closed. \
         The Cedar 'admin' action is unreachable through the claims path."
    );
}

// ===========================================================================
// Complete method -> action -> decision matrix for admin role
// ===========================================================================

#[tokio::test]
async fn test_complete_method_action_matrix() {
    let addr = start_server().await;
    let claims = admin_claims();

    // Every standard HTTP method an admin might use, and the expected outcome.
    let matrix = [
        // (method, expected_decision, reason)
        ("GET",     "Allow",  "read action via rbac-admin-all"),
        ("HEAD",    "Allow",  "read action via rbac-admin-all"),
        ("OPTIONS", "Allow",  "read action via rbac-admin-all"),
        ("POST",    "Allow",  "write action via rbac-admin-all"),
        ("PUT",     "Allow",  "write action via rbac-admin-all"),
        ("PATCH",   "Allow",  "write action via rbac-admin-all"),
        ("DELETE",  "Allow",  "delete action via rbac-admin-all"),
        ("TRACE",   "Deny",   "unknown method, fail-closed"),
        ("CONNECT", "Deny",   "unknown method, fail-closed"),
        ("PURGE",   "Deny",   "unknown method, fail-closed"),
    ];

    for (method, expected, reason) in &matrix {
        let body = authz(addr, method, "/api/v1/data", claims.clone()).await;
        assert_eq!(
            body["decision"].as_str().unwrap(),
            *expected,
            "method {method}: expected {expected} ({reason})"
        );
    }
}

// ===========================================================================
// Viewer role: verify which methods are allowed vs denied
// ===========================================================================

#[tokio::test]
async fn test_viewer_method_permissions() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "action-viewer-matrix",
        "email": "viewer@acme.com",
        "department": "sales",
        "org": "acme",
        "roles": ["viewer"],
        "subscription_tier": "basic",
        "suspended": false,
        "allowed_scopes": ["public"]
    });

    // Viewer: read+list via RBAC, but "list" is unreachable. Also org-scoped
    // grants read+write for same-org. So effective permissions via claims path:
    // GET/HEAD/OPTIONS -> Allow (read via RBAC + org-scoped)
    // POST/PUT/PATCH  -> Allow (write via org-scoped, NOT via RBAC viewer)
    // DELETE           -> Deny  (no policy grants delete to viewer or org-scoped)
    let matrix = [
        ("GET",    "Allow"),
        ("HEAD",   "Allow"),
        ("POST",   "Allow"),  // org-scoped, not RBAC
        ("PUT",    "Allow"),  // org-scoped, not RBAC
        ("DELETE", "Deny"),
    ];

    for (method, expected) in &matrix {
        let body = authz(addr, method, "/api/v1/data", claims.clone()).await;
        assert_eq!(
            body["decision"].as_str().unwrap(),
            *expected,
            "viewer {method}: expected {expected}"
        );
    }
}
