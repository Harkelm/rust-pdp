//! Admin endpoint authentication tests.
//!
//! Covers the auth gate on POST /admin/reload:
//!   - valid Bearer token -> 200
//!   - invalid Bearer token -> 401
//!   - missing Authorization header -> 401
//!   - empty Bearer token -> 401
//!   - wrong auth scheme (Basic) -> 401
//!   - dev mode (None token) -> 200 without auth
//!   - rate limiting after successful auth -> 429

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

const TEST_TOKEN: &str = "test-token-123";

/// Server with admin token configured. All reload requests must present the token.
async fn start_auth_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState = Arc::new(cedar_pdp::handlers::AppContext::new(
        store,
        Some(TEST_TOKEN.to_string()),
    ));

    let app = Router::new()
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Server with no admin token (dev mode). Reload requires no auth.
async fn start_dev_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState =
        Arc::new(cedar_pdp::handlers::AppContext::new(store, None));

    let app = Router::new()
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------------
// Auth-enforced mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reload_valid_token_succeeds() {
    let addr = start_auth_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .header("authorization", format!("Bearer {TEST_TOKEN}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "valid token must be accepted");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["policy_count"].as_u64().unwrap() > 0,
        "reload response must include policy_count"
    );
    assert!(
        body["last_reload_epoch_ms"].as_u64().unwrap() > 0,
        "reload response must include last_reload_epoch_ms"
    );
}

#[tokio::test]
async fn test_reload_invalid_token_rejected() {
    let addr = start_auth_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .header("authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "invalid token must be rejected with 401");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().is_some(),
        "error response must include an error field"
    );
}

#[tokio::test]
async fn test_reload_missing_authorization_header_rejected() {
    let addr = start_auth_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "missing Authorization header must be rejected with 401"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().is_some(),
        "error response must include an error field"
    );
}

#[tokio::test]
async fn test_reload_empty_bearer_token_rejected() {
    let addr = start_auth_server().await;
    let client = reqwest::Client::new();

    // "Bearer " with no token after the space. strip_prefix("Bearer ") yields ""
    // which will not equal TEST_TOKEN.
    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .header("authorization", "Bearer ")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "empty Bearer token must be rejected with 401");
}

#[tokio::test]
async fn test_reload_wrong_auth_scheme_rejected() {
    let addr = start_auth_server().await;
    let client = reqwest::Client::new();

    // Basic scheme: strip_prefix("Bearer ") returns None, so the match arm
    // falls through to the wildcard _ => Err(401).
    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .header("authorization", "Basic dXNlcjpwYXNz")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "Basic auth scheme must be rejected with 401 (only Bearer is accepted)"
    );
}

// ---------------------------------------------------------------------------
// Dev mode (no token configured)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reload_dev_mode_no_auth_required() {
    let addr = start_dev_server().await;
    let client = reqwest::Client::new();

    // No Authorization header at all -- dev mode allows unrestricted access.
    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "dev mode (no token configured) must allow reload without auth"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["policy_count"].as_u64().unwrap() > 0,
        "dev mode reload must return policy_count"
    );
}

// ---------------------------------------------------------------------------
// Rate limiting (auth-enforced mode)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reload_rate_limited_after_valid_auth() {
    let addr = start_auth_server().await;
    let client = reqwest::Client::new();

    // First request: must succeed.
    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .header("authorization", format!("Bearer {TEST_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "first reload with valid token must succeed");

    // Immediate second request: must be rate-limited (429).
    // The rate limit fires after auth passes, so we still need the token.
    let resp = client
        .post(format!("http://{addr}/admin/reload"))
        .header("authorization", format!("Bearer {TEST_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "rapid second reload must be rate-limited even with valid token"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("rate limited"),
        "rate-limit error must mention 'rate limited'"
    );
}
