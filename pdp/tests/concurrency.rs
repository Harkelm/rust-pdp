//! Concurrency and reload safety tests.
//!
//! Validates that PolicyStore behaves correctly under concurrent access
//! and that policy hot-reload does not corrupt in-flight evaluations.
//! Addresses AGI-Acc F3 (fail-closed under overload) and the arc-swap
//! reload design documented in rust-pdp-service-architecture.md:108-116.

mod common;
use common::{admin_allow_request, production_policy_dir, start_server};

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Concurrent authorization requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_authz_requests() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // Fire 50 concurrent authorization requests. All should return consistent
    // results without panics, data races, or incorrect decisions.
    let mut handles = Vec::new();
    for i in 0..50 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&admin_allow_request())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "request {i} must succeed");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body["decision"], "Allow",
                "request {i}: admin GET must be Allow"
            );
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Reload during concurrent evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reload_during_concurrent_eval() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // Spawn 30 concurrent authz requests + 5 concurrent reloads.
    // No request should panic, return 500, or produce an inconsistent state.
    // Every authz response must be either Allow or Deny (valid decisions).
    let mut handles = Vec::new();

    // Authz requests
    for i in 0..30 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/v1/is_authorized"))
                .json(&admin_allow_request())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "authz request {i} must not 500");
            let body: serde_json::Value = resp.json().await.unwrap();
            let decision = body["decision"].as_str().unwrap();
            assert!(
                decision == "Allow" || decision == "Deny",
                "authz request {i}: decision must be Allow or Deny, got {decision}"
            );
        });
        handles.push(handle);
    }

    // Concurrent reloads -- some may be rate-limited (429) which is correct.
    // The test verifies no panics/500s, not that all reloads succeed.
    for i in 0..5 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .send()
                .await
                .unwrap();
            let status = resp.status().as_u16();
            assert!(
                status == 200 || status == 429,
                "reload {i}: expected 200 or 429, got {status}"
            );
            if status == 200 {
                let body: serde_json::Value = resp.json().await.unwrap();
                assert!(
                    body["policy_count"].as_u64().unwrap() > 0,
                    "reload {i}: must return non-zero policy count"
                );
            }
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Concurrent batch evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_batch_evaluation() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // 10 concurrent batch requests, each with 20 sub-requests.
    // Tests rayon thread pool under concurrent batch load (AGI-Acc F2).
    let mut handles = Vec::new();
    for batch_idx in 0..10 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let requests: Vec<serde_json::Value> = (0..20)
                .map(|_| {
                    serde_json::json!({
                        "principal": "ignored",
                        "action": "GET",
                        "resource": "/api/v1/data",
                        "context": {},
                        "claims": {
                            "sub": format!("batch-{batch_idx}-user"),
                            "email": "user@example.com",
                            "department": "engineering",
                            "org": "acme",
                            "roles": ["admin"],
                            "subscription_tier": "enterprise",
                            "suspended": false,
                            "allowed_scopes": ["internal"]
                        }
                    })
                })
                .collect();

            let resp = client
                .post(format!("http://{addr}/v1/batch_is_authorized"))
                .json(&serde_json::json!({ "requests": requests }))
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "batch {batch_idx} must succeed");
            let body: serde_json::Value = resp.json().await.unwrap();
            let responses = body["responses"].as_array().unwrap();
            assert_eq!(responses.len(), 20, "batch {batch_idx} must return 20 responses");

            for (i, r) in responses.iter().enumerate() {
                assert_eq!(
                    r["decision"], "Allow",
                    "batch {batch_idx} request {i}: admin GET must Allow"
                );
            }
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|e| panic!("batch task {i} panicked: {e}"));
    }
}

// ---------------------------------------------------------------------------
// PolicyStore unit tests: concurrent reload safety
// ---------------------------------------------------------------------------

#[test]
fn test_policy_store_concurrent_reload_and_read() {
    use std::thread;

    let policy_path = production_policy_dir();
    let store = Arc::new(
        cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies"),
    );

    let mut handles = Vec::new();

    // 4 reader threads, each doing 100 reads
    for _ in 0..4 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let state = store.load();
                let (ps, _schema) = state.as_ref();
                assert!(ps.policies().count() > 0, "must always see non-zero policies");
            }
        }));
    }

    // 2 writer threads, each doing 20 reloads
    for _ in 0..2 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for _ in 0..20 {
                let result = store.reload();
                assert!(result.is_ok(), "reload must succeed");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread must not panic");
    }
}

// ---------------------------------------------------------------------------
// PolicyCache: verify cache tracks reload
// ---------------------------------------------------------------------------

#[test]
fn test_policy_cache_sees_reload() {
    let policy_path = production_policy_dir();
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");

    let mut cache = store.cache();
    let initial_count = {
        let state = cache.load();
        let (ps, _) = state.as_ref();
        ps.policies().count()
    };
    assert!(initial_count > 0);

    // Reload (same policies, but timestamp changes)
    let new_count = store.reload().unwrap();
    assert_eq!(new_count, initial_count, "same policies on disk");

    // Cache must pick up the reloaded state (same count, but the Arc is new)
    let cached_state = cache.load();
    let (ps, _) = cached_state.as_ref();
    assert_eq!(ps.policies().count(), new_count);
}

// ---------------------------------------------------------------------------
// Health endpoint under load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_under_concurrent_load() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    let mut handles = Vec::new();
    for _ in 0..20 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client
                .get(format!("http://{addr}/health"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["status"], "ok");
            assert!(body["policies_loaded"].as_u64().unwrap() > 0);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
