//! Extreme stress tests -- push concurrency, batch sizes, and mixed workloads
//! to find breaking points and verify correctness under pressure.
//!
//! These tests complement the Criterion benchmarks (which measure latency) by
//! verifying *correctness* at scale: every response must be a valid decision,
//! no 500s, no dropped connections, no panics.
//!
//! The concurrency numbers here (500-1000) are well beyond expected production
//! load for a sidecar PDP. The goal is to find the ceiling so the team knows
//! where admission control (tower::ConcurrencyLimit) becomes necessary.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

/// Start server with admin token set for auth testing.
async fn start_server_with_auth(token: &str) -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState = Arc::new(
        cedar_pdp::handlers::AppContext::new(store, Some(token.to_string())),
    );

    let app = Router::new()
        .route("/v1/is_authorized", post(cedar_pdp::handlers::is_authorized))
        .route("/v1/batch_is_authorized", post(cedar_pdp::handlers::batch_is_authorized))
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/healthz", get(cedar_pdp::handlers::healthz))
        .route("/readyz", get(cedar_pdp::handlers::readyz))
        .route("/health", get(cedar_pdp::handlers::health))
        .layer(middleware::from_fn(cedar_pdp::handlers::request_id_layer))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Start server without admin token (dev mode).
async fn start_server_open() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState =
        Arc::new(cedar_pdp::handlers::AppContext::new(store, None));

    let app = Router::new()
        .route("/v1/is_authorized", post(cedar_pdp::handlers::is_authorized))
        .route("/v1/batch_is_authorized", post(cedar_pdp::handlers::batch_is_authorized))
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/healthz", get(cedar_pdp::handlers::healthz))
        .route("/readyz", get(cedar_pdp::handlers::readyz))
        .route("/health", get(cedar_pdp::handlers::health))
        .layer(middleware::from_fn(cedar_pdp::handlers::request_id_layer))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn admin_allow_request() -> serde_json::Value {
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

fn viewer_deny_request() -> serde_json::Value {
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

fn suspended_deny_request() -> serde_json::Value {
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
// c=500 single authz -- all responses must be correct decisions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_500_concurrent_authz_all_correct() {
    let addr = start_server_open().await;
    let client = reqwest::Client::new();
    let allow_count = Arc::new(AtomicUsize::new(0));
    let deny_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..500 {
        let client = client.clone();
        let ac = Arc::clone(&allow_count);
        let dc = Arc::clone(&deny_count);

        // Alternate between allow and deny requests for a realistic mix.
        let (req, expected) = if i % 2 == 0 {
            (admin_allow_request(), "Allow")
        } else {
            (viewer_deny_request(), "Deny")
        };

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "request {i} must not error");
            let body: serde_json::Value = resp.json().await.unwrap();
            let decision = body["decision"].as_str().unwrap();
            assert_eq!(
                decision, expected,
                "request {i}: expected {expected}, got {decision}"
            );
            if decision == "Allow" {
                ac.fetch_add(1, Ordering::Relaxed);
            } else {
                dc.fetch_add(1, Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }

    assert_eq!(allow_count.load(Ordering::Relaxed), 250);
    assert_eq!(deny_count.load(Ordering::Relaxed), 250);
}

// ---------------------------------------------------------------------------
// c=1000 single authz -- find the ceiling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_1000_concurrent_authz_no_errors() {
    let addr = start_server_open().await;
    let client = reqwest::Client::new();
    let success = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..1000 {
        let client = client.clone();
        let sc = Arc::clone(&success);
        let req = if i % 3 == 0 {
            suspended_deny_request()
        } else if i % 3 == 1 {
            admin_allow_request()
        } else {
            viewer_deny_request()
        };

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "request {i} returned {}", resp.status());
            let body: serde_json::Value = resp.json().await.unwrap();
            let decision = body["decision"].as_str().unwrap();

            // Verify correctness based on request type.
            let expected = if i % 3 == 1 { "Allow" } else { "Deny" };
            assert_eq!(
                decision, expected,
                "request {i}: expected {expected}, got {decision}"
            );
            sc.fetch_add(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }

    let elapsed = start.elapsed();
    let total = success.load(Ordering::Relaxed);
    assert_eq!(total, 1000, "all 1000 requests must succeed");

    // Log throughput for human review (not a pass/fail assertion).
    eprintln!(
        "stress: 1000 concurrent authz completed in {:.1}ms ({:.0} req/s)",
        elapsed.as_secs_f64() * 1000.0,
        1000.0 / elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// c=100 x batch_100 = 10,000 concurrent decisions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_100_concurrent_max_batches() {
    let addr = start_server_open().await;
    let client = reqwest::Client::new();
    let total_decisions = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut handles = Vec::new();
    for batch_idx in 0..100 {
        let client = client.clone();
        let td = Arc::clone(&total_decisions);

        let handle = tokio::spawn(async move {
            // Build 100-item batch (the maximum allowed).
            let requests: Vec<serde_json::Value> = (0..100)
                .map(|j| {
                    if (batch_idx + j) % 2 == 0 {
                        admin_allow_request()
                    } else {
                        viewer_deny_request()
                    }
                })
                .collect();

            let resp = client
                .post(format!("http://{addr}/v1/batch_is_authorized"))
                .json(&serde_json::json!({ "requests": requests }))
                .send()
                .await
                .unwrap();

            assert_eq!(
                resp.status(),
                200,
                "batch {batch_idx} must succeed, got {}",
                resp.status()
            );

            let body: serde_json::Value = resp.json().await.unwrap();
            let responses = body["responses"].as_array().unwrap();
            assert_eq!(
                responses.len(),
                100,
                "batch {batch_idx} must return 100 responses"
            );

            // Verify every decision is correct.
            for (j, r) in responses.iter().enumerate() {
                let decision = r["decision"].as_str().unwrap();
                let expected = if (batch_idx + j) % 2 == 0 { "Allow" } else { "Deny" };
                assert_eq!(
                    decision, expected,
                    "batch {batch_idx} item {j}: expected {expected}, got {decision}"
                );
            }

            td.fetch_add(100, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("batch {i} panicked: {e}"));
    }

    let elapsed = start.elapsed();
    let total = total_decisions.load(Ordering::Relaxed);
    assert_eq!(total, 10_000, "all 10,000 decisions must complete");

    eprintln!(
        "stress: 100 x batch_100 = 10,000 decisions in {:.1}ms ({:.0} decisions/s)",
        elapsed.as_secs_f64() * 1000.0,
        10_000.0 / elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// X-Request-Id: verify every response has one, and client-supplied IDs echo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_request_id_present_under_load() {
    let addr = start_server_open().await;
    let client = reqwest::Client::new();

    let mut handles = Vec::new();
    for i in 0..200 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let mut builder = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&admin_allow_request());

            // Half the requests supply their own ID, half let the server generate.
            let supplied_id = if i % 2 == 0 {
                let id = format!("client-{i}");
                builder = builder.header("x-request-id", &id);
                Some(id)
            } else {
                None
            };

            let resp = builder.send().await.unwrap();
            assert_eq!(resp.status(), 200);

            let returned_id = resp
                .headers()
                .get("x-request-id")
                .expect("response must have x-request-id header")
                .to_str()
                .unwrap()
                .to_string();

            if let Some(expected) = supplied_id {
                assert_eq!(
                    returned_id, expected,
                    "request {i}: client-supplied ID must be echoed"
                );
            } else {
                // Server-generated: should be a valid UUID v4 (36 chars with hyphens).
                assert_eq!(
                    returned_id.len(),
                    36,
                    "request {i}: server-generated ID should be UUID format, got '{returned_id}'"
                );
            }
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Admin auth: verify token enforcement under concurrent load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_auth_enforced_under_load() {
    let token = "test-secret-token-12345";
    let addr = start_server_with_auth(token).await;
    let client = reqwest::Client::new();

    let mut handles = Vec::new();

    // 50 requests with correct token -- all must succeed.
    for i in 0..50 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .header("authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                200,
                "authed reload {i} must succeed, got {}",
                resp.status()
            );
        });
        handles.push(handle);
    }

    // 50 requests without token -- all must be 401.
    for i in 0..50 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                401,
                "unauthed reload {i} must be 401, got {}",
                resp.status()
            );
        });
        handles.push(handle);
    }

    // 50 requests with wrong token -- all must be 401.
    for i in 0..50 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .header("authorization", "Bearer wrong-token")
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                401,
                "bad-token reload {i} must be 401, got {}",
                resp.status()
            );
        });
        handles.push(handle);
    }

    // Simultaneously: 100 authz requests must be unaffected by admin load.
    for i in 0..100 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&admin_allow_request())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "authz {i} must not be affected by admin load");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["decision"], "Allow");
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Health probes: /healthz and /readyz under mixed concurrent load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_probes_under_authz_load() {
    let addr = start_server_open().await;
    let client = reqwest::Client::new();

    let mut handles = Vec::new();

    // 200 authz requests as background load.
    for i in 0..200 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&admin_allow_request())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "authz {i} must succeed");
        });
        handles.push(handle);
    }

    // Interleaved: 50 healthz probes must always return 200 instantly.
    for i in 0..50 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .get(format!("http://{addr}/healthz"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "healthz {i} must be 200");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["status"], "ok");
        });
        handles.push(handle);
    }

    // Interleaved: 50 readyz probes must report policies loaded.
    for i in 0..50 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .get(format!("http://{addr}/readyz"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "readyz {i} must be 200");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert!(
                body["policies_loaded"].as_u64().unwrap() > 0,
                "readyz {i}: must report policies loaded"
            );
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Mixed workload: authz + batch + reload + health, all concurrent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mixed_workload_under_extreme_concurrency() {
    let addr = start_server_open().await;
    let client = reqwest::Client::new();
    let start = Instant::now();

    let mut handles = Vec::new();

    // 300 single authz (mixed allow/deny/suspended).
    for i in 0..300 {
        let client = client.clone();
        let req = match i % 3 {
            0 => admin_allow_request(),
            1 => viewer_deny_request(),
            _ => suspended_deny_request(),
        };
        let expected = if i % 3 == 0 { "Allow" } else { "Deny" };

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&req)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["decision"], expected, "authz {i}");
        });
        handles.push(handle);
    }

    // 20 batch_50 requests (1000 decisions).
    for batch_idx in 0..20 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let requests: Vec<serde_json::Value> =
                (0..50).map(|_| admin_allow_request()).collect();
            let resp = client
                .post(format!("http://{addr}/v1/batch_is_authorized"))
                .json(&serde_json::json!({ "requests": requests }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "batch {batch_idx}");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["responses"].as_array().unwrap().len(), 50);
        });
        handles.push(handle);
    }

    // 10 concurrent reloads (safe due to arc-swap).
    for i in 0..10 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "reload {i}");
        });
        handles.push(handle);
    }

    // 20 health probes.
    for _ in 0..20 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .get(format!("http://{addr}/healthz"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }

    let elapsed = start.elapsed();
    // 300 single + 20*50 batch + 10 reload + 20 health = 1330 HTTP requests, 1300 decisions.
    eprintln!(
        "stress: mixed workload (300 authz + 20 batch_50 + 10 reload + 20 health) \
         completed in {:.1}ms",
        elapsed.as_secs_f64() * 1000.0,
    );
}
