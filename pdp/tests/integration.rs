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
async fn test_permit_decision() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // alice has a direct permit policy for ViewResource
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "User::\"alice\"",
            "action": "Action::\"ViewResource\"",
            "resource": "ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Allow");
    // The determining policy should be "alice-view"
    let reasons = body["diagnostics"]["reason"].as_array().unwrap();
    assert!(!reasons.is_empty(), "expected at least one determining policy");
}

#[tokio::test]
async fn test_deny_decision() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Unknown action -- no permit policy matches, so deny.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "User::\"bob\"",
            "action": "Action::\"DeleteResource\"",
            "resource": "ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Deny");
    assert!(body["diagnostics"]["reason"].as_array().unwrap().is_empty());
}
