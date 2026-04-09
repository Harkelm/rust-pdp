#![allow(dead_code)]
//! Shared test utilities for integration tests.
//!
//! Request builders, claims builders, and server starters used across multiple
//! test files. Avoids duplicating identical helper functions in each test binary.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Policy directory helpers
// ---------------------------------------------------------------------------

/// Returns the path to the production Cedar policies directory (../policies
/// relative to the pdp crate root).
pub fn production_policy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies")
}

// ---------------------------------------------------------------------------
// Server starters
// ---------------------------------------------------------------------------

/// Start a test server with the standard route set (is_authorized,
/// batch_is_authorized, admin/reload, health) using policies from `policy_dir`.
///
/// No admin token -- admin endpoints are unrestricted in test mode.
pub async fn start_server(policy_dir: PathBuf) -> SocketAddr {
    let store =
        cedar_pdp::policy::PolicyStore::from_dir(&policy_dir).expect("load policies");
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
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// Admin user request that should be allowed (alice, admin role, GET /api/v1/users).
pub fn admin_allow_request() -> serde_json::Value {
    serde_json::json!({
        "principal": "ignored",
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
    })
}

/// Viewer user request that should be denied (bob, viewer role, DELETE /api/v1/data).
pub fn viewer_deny_request() -> serde_json::Value {
    serde_json::json!({
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
    })
}

/// Suspended admin request that should be denied (suspended=true overrides admin role).
pub fn suspended_deny_request() -> serde_json::Value {
    serde_json::json!({
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
    })
}

// ---------------------------------------------------------------------------
// Claims builders
// ---------------------------------------------------------------------------

/// Admin claims for diagnostics testing.
pub fn admin_claims() -> serde_json::Value {
    serde_json::json!({
        "sub": "diag-admin",
        "email": "admin@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["admin"],
        "subscription_tier": "enterprise",
        "suspended": false,
        "allowed_scopes": ["internal"]
    })
}

/// Viewer claims for diagnostics testing.
pub fn viewer_claims() -> serde_json::Value {
    serde_json::json!({
        "sub": "diag-viewer",
        "email": "viewer@acme.com",
        "department": "sales",
        "org": "acme",
        "roles": ["viewer"],
        "subscription_tier": "basic",
        "suspended": false,
        "allowed_scopes": ["public"]
    })
}
