//! AVP endpoint stress tests -- concurrency, throughput, error storms, and
//! comparative latency against native endpoints.
//!
//! Uses the test policy set (pdp/policies/) for AVP endpoints and validates
//! correctness at scale. Complements avp_compat.rs (functional) and stress.rs
//! (native endpoints).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

async fn start_avp_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
    let state: cedar_pdp::handlers::AppState =
        Arc::new(cedar_pdp::handlers::AppContext::new(store, None));

    let app = Router::new()
        .route(
            "/v1/is_authorized",
            post(cedar_pdp::handlers::is_authorized),
        )
        .route(
            "/avp/is-authorized",
            post(cedar_pdp::handlers::avp_is_authorized),
        )
        .route(
            "/avp/batch-is-authorized",
            post(cedar_pdp::handlers::avp_batch_is_authorized),
        )
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn avp_admin_allow_request() -> Value {
    json!({
        "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
        "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
        "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
        "entities": {
            "entityList": [
                {
                    "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                    "Attributes": { "email": { "String": "alice@example.com" } },
                    "Parents": [{ "EntityType": "ApiGateway::Role", "EntityId": "admin" }]
                },
                { "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" }, "Attributes": {}, "Parents": [] },
                { "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/api/data" }, "Attributes": {}, "Parents": [] }
            ]
        }
    })
}

fn avp_viewer_deny_request() -> Value {
    json!({
        "principal": { "entityType": "ApiGateway::User", "entityId": "bob" },
        "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
        "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
        "entities": {
            "entityList": [
                {
                    "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "bob" },
                    "Attributes": { "email": { "String": "bob@example.com" } },
                    "Parents": [{ "EntityType": "ApiGateway::Role", "EntityId": "viewer" }]
                },
                { "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "viewer" }, "Attributes": {}, "Parents": [] },
                { "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/api/data" }, "Attributes": {}, "Parents": [] }
            ]
        }
    })
}

fn avp_malformed_request() -> Value {
    json!({
        "principal": { "entityType": "ApiGateway::User", "entityId": "bad" },
        "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
        "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" },
        "entities": {
            "entityList": [{
                "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "bad" },
                "Attributes": { "email": { "Float": 3.14 } },
                "Parents": []
            }]
        }
    })
}

// ---------------------------------------------------------------------------
// c=500 AVP single authz -- all responses must be correct decisions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_500_concurrent_single_all_correct() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();
    let allow_count = Arc::new(AtomicUsize::new(0));
    let deny_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..500 {
        let client = client.clone();
        let ac = Arc::clone(&allow_count);
        let dc = Arc::clone(&deny_count);

        let (req, expected) = if i % 2 == 0 {
            (avp_admin_allow_request(), "ALLOW")
        } else {
            (avp_viewer_deny_request(), "DENY")
        };

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/avp/is-authorized"))
                .json(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "request {i} must not error");
            let body: Value = resp.json().await.unwrap();
            let decision = body["decision"].as_str().unwrap();
            assert_eq!(
                decision, expected,
                "request {i}: expected {expected}, got {decision}"
            );
            if decision == "ALLOW" {
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
// c=1000 AVP single authz -- ceiling test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_1000_concurrent_single_no_errors() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();
    let success = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..1000 {
        let client = client.clone();
        let sc = Arc::clone(&success);
        let (req, expected) = if i % 2 == 0 {
            (avp_admin_allow_request(), "ALLOW")
        } else {
            (avp_viewer_deny_request(), "DENY")
        };

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/avp/is-authorized"))
                .json(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "request {i} returned {}", resp.status());
            let body: Value = resp.json().await.unwrap();
            let decision = body["decision"].as_str().unwrap();
            assert_eq!(decision, expected, "request {i}");
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

    eprintln!(
        "avp stress: 1000 concurrent single authz in {:.1}ms ({:.0} req/s)",
        elapsed.as_secs_f64() * 1000.0,
        1000.0 / elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// c=50 x batch_30 = 1,500 AVP batch decisions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_50_concurrent_max_batches() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();
    let total_decisions = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut handles = Vec::new();
    for batch_idx in 0..50 {
        let client = client.clone();
        let td = Arc::clone(&total_decisions);

        let handle = tokio::spawn(async move {
            // Build 30-item batch (AVP maximum). Same principal for homogeneity.
            let requests: Vec<Value> = (0..30)
                .map(|j| {
                    let action = if (batch_idx + j) % 3 == 0 { "write" } else { "read" };
                    json!({
                        "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                        "action": { "actionType": "ApiGateway::Action", "actionId": action },
                        "resource": { "entityType": "ApiGateway::ApiResource", "entityId": format!("/api/res/{j}") }
                    })
                })
                .collect();

            // Shared entities for the batch.
            let mut entity_list: Vec<Value> = vec![
                json!({
                    "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                    "Attributes": { "email": { "String": "alice@example.com" } },
                    "Parents": [{ "EntityType": "ApiGateway::Role", "EntityId": "admin" }]
                }),
                json!({ "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" }, "Attributes": {}, "Parents": [] }),
            ];
            for j in 0..30 {
                entity_list.push(json!({
                    "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": format!("/api/res/{j}") },
                    "Attributes": {}, "Parents": []
                }));
            }

            let resp = client
                .post(format!("http://{addr}/avp/batch-is-authorized"))
                .json(&json!({
                    "entities": { "entityList": entity_list },
                    "requests": requests
                }))
                .send()
                .await
                .unwrap();

            assert_eq!(
                resp.status(), 200,
                "batch {batch_idx} must succeed, got {}", resp.status()
            );

            let body: Value = resp.json().await.unwrap();
            let results = body["results"].as_array().unwrap();
            assert_eq!(results.len(), 30, "batch {batch_idx} must return 30 results");

            // Admin has full access -- all should be ALLOW.
            for (j, r) in results.iter().enumerate() {
                assert_eq!(
                    r["decision"], "ALLOW",
                    "batch {batch_idx} item {j}: admin should ALLOW"
                );
            }

            td.fetch_add(30, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("batch {i} panicked: {e}"));
    }

    let elapsed = start.elapsed();
    let total = total_decisions.load(Ordering::Relaxed);
    assert_eq!(total, 1500, "all 1,500 decisions must complete");

    eprintln!(
        "avp stress: 50 x batch_30 = 1,500 decisions in {:.1}ms ({:.0} decisions/s)",
        elapsed.as_secs_f64() * 1000.0,
        1500.0 / elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// Error storm: 200 concurrent malformed requests -- all must fail-closed DENY
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_error_storm_all_fail_closed() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();
    let deny_with_error = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..200 {
        let client = client.clone();
        let de = Arc::clone(&deny_with_error);

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/avp/is-authorized"))
                .json(&avp_malformed_request())
                .send()
                .await
                .unwrap();

            // Must be 200 (not 500) -- error surfaces as DENY, not server error.
            assert_eq!(resp.status(), 200, "error request {i} must return 200");
            let body: Value = resp.json().await.unwrap();
            assert_eq!(body["decision"], "DENY", "error request {i} must DENY");
            assert!(
                !body["errors"].as_array().unwrap().is_empty(),
                "error request {i} must have error description"
            );
            de.fetch_add(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }

    assert_eq!(deny_with_error.load(Ordering::Relaxed), 200);
}

// ---------------------------------------------------------------------------
// Mixed error + valid: 50% good, 50% bad, all concurrent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_mixed_valid_and_malformed() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();
    let allow_count = Arc::new(AtomicUsize::new(0));
    let deny_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..300 {
        let client = client.clone();
        let ac = Arc::clone(&allow_count);
        let dc = Arc::clone(&deny_count);
        let ec = Arc::clone(&error_count);

        let handle = tokio::spawn(async move {
            let req = match i % 3 {
                0 => avp_admin_allow_request(),
                1 => avp_viewer_deny_request(),
                _ => avp_malformed_request(),
            };

            let resp = client
                .post(format!("http://{addr}/avp/is-authorized"))
                .json(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "request {i}");
            let body: Value = resp.json().await.unwrap();
            let decision = body["decision"].as_str().unwrap();
            let has_errors = !body["errors"].as_array().unwrap().is_empty();

            match i % 3 {
                0 => {
                    assert_eq!(decision, "ALLOW", "admin request {i}");
                    ac.fetch_add(1, Ordering::Relaxed);
                }
                1 => {
                    assert_eq!(decision, "DENY", "viewer write request {i}");
                    dc.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    assert_eq!(decision, "DENY", "malformed request {i}");
                    assert!(has_errors, "malformed request {i} must have errors");
                    ec.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle.await.unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }

    assert_eq!(allow_count.load(Ordering::Relaxed), 100);
    assert_eq!(deny_count.load(Ordering::Relaxed), 100);
    assert_eq!(error_count.load(Ordering::Relaxed), 100);
}

// ---------------------------------------------------------------------------
// AVP vs Native latency comparison -- same decisions, measure overhead
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_latency_comparison_vs_native() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Warm up both endpoints.
    for _ in 0..10 {
        client
            .post(format!("http://{addr}/avp/is-authorized"))
            .json(&avp_admin_allow_request())
            .send()
            .await
            .unwrap();
    }

    let n = 200;

    // Measure AVP endpoint: sequential for stable latency measurement.
    let avp_start = Instant::now();
    for _ in 0..n {
        let resp = client
            .post(format!("http://{addr}/avp/is-authorized"))
            .json(&avp_admin_allow_request())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["decision"], "ALLOW");
    }
    let avp_elapsed = avp_start.elapsed();

    // Measure native endpoint with equivalent request.
    // The native endpoint uses the test policy set too (same server).
    // Use Cedar UID string format for the native endpoint.
    let native_req = json!({
        "principal": "ApiGateway::User::\"alice\"",
        "action": "ApiGateway::Action::\"read\"",
        "resource": "ApiGateway::ApiResource::\"/api/data\"",
        "context": {}
    });

    let native_start = Instant::now();
    for _ in 0..n {
        let resp = client
            .post(format!("http://{addr}/v1/is_authorized"))
            .json(&native_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        // Native without claims uses empty entities -- will DENY (no entities to match).
        // That's fine -- we're measuring HTTP round-trip + parsing overhead, not policy match.
    }
    let native_elapsed = native_start.elapsed();

    let avp_per_req_us = avp_elapsed.as_micros() as f64 / n as f64;
    let native_per_req_us = native_elapsed.as_micros() as f64 / n as f64;
    let overhead_pct = ((avp_per_req_us / native_per_req_us) - 1.0) * 100.0;

    eprintln!(
        "avp vs native latency ({n} sequential requests):\n  \
         AVP:    {avp_per_req_us:.0} us/req\n  \
         Native: {native_per_req_us:.0} us/req\n  \
         Overhead: {overhead_pct:.1}%"
    );

    // The overhead should be reasonable. AVP does more JSON parsing (typed values,
    // entity construction from explicit list) but skips JWT claim processing.
    // No hard threshold -- this is informational for the tech director.
}

// ---------------------------------------------------------------------------
// Sustained throughput: 2000 concurrent AVP requests (find the wall)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_stress_2000_concurrent_sustained() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();
    let success = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..2000 {
        let client = client.clone();
        let sc = Arc::clone(&success);
        let ec = Arc::clone(&errors);

        let req = if i % 2 == 0 {
            avp_admin_allow_request()
        } else {
            avp_viewer_deny_request()
        };

        let handle = tokio::spawn(async move {
            match client
                .post(format!("http://{addr}/avp/is-authorized"))
                .json(&req)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status() == 200 {
                        sc.fetch_add(1, Ordering::Relaxed);
                    } else {
                        ec.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    ec.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let total_success = success.load(Ordering::Relaxed);
    let total_errors = errors.load(Ordering::Relaxed);

    eprintln!(
        "avp stress: 2000 concurrent -- {total_success} success, {total_errors} errors in {:.1}ms ({:.0} req/s)",
        elapsed.as_secs_f64() * 1000.0,
        2000.0 / elapsed.as_secs_f64()
    );

    // All 2000 should succeed -- no connection drops or panics.
    assert_eq!(total_errors, 0, "no errors at c=2000");
    assert_eq!(total_success, 2000);
}
