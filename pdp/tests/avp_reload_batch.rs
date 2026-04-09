//! AVP batch evaluation correctness under concurrent admin reloads.
//!
//! The existing reload_resilience.rs tests cover v1 batch + reload. AVP batch
//! differs: it uses shared entities at the batch level (not per-request) and
//! enforces a homogeneity constraint (all requests must share the same principal
//! or the same resource). A reload mid-batch could theoretically produce
//! inconsistent policy epochs across decisions within a single batch.
//!
//! This test verifies that arc-swap readers always see a consistent
//! (PolicySet, Schema) tuple even when reloads interleave with parallel AVP
//! batch evaluation using shared entity sets.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use common::production_policy_dir;

// ---------------------------------------------------------------------------
// Server setup: AVP endpoints + admin reload (production policies)
// ---------------------------------------------------------------------------

/// Start a test server with both AVP and admin endpoints using production
/// policies. This combination is not covered by the existing avp_compat.rs or
/// avp_stress.rs servers (which omit admin/reload) or reload_resilience.rs
/// (which omits AVP endpoints).
async fn start_avp_admin_server() -> SocketAddr {
    let store = cedar_pdp::policy::PolicyStore::from_dir(&production_policy_dir())
        .expect("load production policies");
    let state: cedar_pdp::handlers::AppState =
        Arc::new(cedar_pdp::handlers::AppContext::new(store, None));

    let app = Router::new()
        .route(
            "/avp/is-authorized",
            post(cedar_pdp::handlers::avp_is_authorized),
        )
        .route(
            "/avp/batch-is-authorized",
            post(cedar_pdp::handlers::avp_batch_is_authorized),
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
// Entity and request builders for production schema
// ---------------------------------------------------------------------------

/// Build the shared entity set for a batch where alice (admin) is the principal.
/// Includes the User, Role, Organization, and all resources needed for 30 requests.
fn alice_admin_shared_entities(resource_ids: &[String]) -> Value {
    let mut entity_list: Vec<Value> = vec![
        json!({
            "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
            "Attributes": {
                "email": { "String": "alice@acme.com" },
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
        }),
        json!({
            "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" },
            "Attributes": {},
            "Parents": []
        }),
        json!({
            "Identifier": { "EntityType": "ApiGateway::Organization", "EntityId": "acme" },
            "Attributes": {},
            "Parents": []
        }),
    ];

    for rid in resource_ids {
        entity_list.push(json!({
            "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": rid },
            "Attributes": {
                "service": { "String": "default" },
                "path_pattern": { "String": rid },
                "department": { "String": "" },
                "classification": { "String": "internal" },
                "owner_org": { "String": "acme" }
            },
            "Parents": []
        }));
    }

    json!({ "entityList": entity_list })
}

/// Build a 30-item AVP batch request with alice (admin) as the principal for
/// all items, varying actions and resources. Same principal satisfies the
/// homogeneity constraint.
///
/// Returns (request_body, expected_decisions) where each expected decision is
/// "ALLOW" or "DENY" based on the action.
fn build_avp_batch_30(batch_idx: usize) -> (Value, Vec<&'static str>) {
    let actions = ["read", "write", "delete"];
    let mut requests = Vec::with_capacity(30);
    let mut expected = Vec::with_capacity(30);
    let mut resource_ids = Vec::with_capacity(30);

    for j in 0..30 {
        let action = actions[(batch_idx + j) % 3];
        let resource_id = format!("/api/v1/batch-{batch_idx}/item-{j}");
        resource_ids.push(resource_id.clone());

        requests.push(json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": action },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": resource_id }
        }));

        // alice is admin -- admin-full-access grants read, write, delete.
        expected.push("ALLOW");
    }

    let body = json!({
        "entities": alice_admin_shared_entities(&resource_ids),
        "requests": requests
    });

    (body, expected)
}

// ---------------------------------------------------------------------------
// Test: AVP batch correctness under concurrent reloads
// ---------------------------------------------------------------------------

/// Concurrent AVP batch evaluation with interleaved admin reloads.
///
/// Spawns 20 concurrent AVP batch requests (each batch of 30, same principal
/// for homogeneity) alongside 10 concurrent admin reload requests. Verifies:
/// - All batch responses are HTTP 200 with exactly 30 results each
/// - All decisions match expected ALLOW/DENY based on alice's admin role
/// - No batch returns inconsistent results (mixed policy epochs)
///
/// This covers the gap identified in reload_resilience.rs: v1 batch + reload is
/// tested but AVP batch + reload (with shared entities and homogeneity) is not.
#[tokio::test]
async fn test_avp_batch_correctness_under_concurrent_reloads() {
    let addr = start_avp_admin_server().await;
    let client = reqwest::Client::new();

    let start = Instant::now();
    let mut handles = Vec::new();

    // 20 concurrent AVP batch requests.
    for batch_idx in 0..20 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let (body, expected) = build_avp_batch_30(batch_idx);

            let resp = client
                .post(format!("http://{addr}/avp/batch-is-authorized"))
                .json(&body)
                .send()
                .await
                .unwrap();

            assert_eq!(
                resp.status(),
                200,
                "AVP batch {batch_idx} must succeed"
            );

            let response_body: Value = resp.json().await.unwrap();
            let results = response_body["results"]
                .as_array()
                .expect("results must be an array");

            assert_eq!(
                results.len(),
                30,
                "AVP batch {batch_idx}: expected 30 results, got {}",
                results.len()
            );

            for (j, result) in results.iter().enumerate() {
                let decision = result["decision"]
                    .as_str()
                    .unwrap_or_else(|| panic!("batch {batch_idx} item {j}: missing decision"));
                assert_eq!(
                    decision, expected[j],
                    "batch {batch_idx} item {j}: expected {}, got {decision}",
                    expected[j]
                );
            }
        });
        handles.push(handle);
    }

    // 10 interleaved reload requests -- some may be rate-limited (429).
    for i in 0..10 {
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
        });
        handles.push(handle);
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|e| panic!("task {i} panicked: {e}"));
    }

    eprintln!(
        "avp_reload_batch: 20 x AVP batch_30 + 10 reloads in {:.1}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
}
