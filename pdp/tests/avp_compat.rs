//! Integration tests for AVP-compatible authorization endpoints.
//!
//! Tests the /avp/is-authorized and /avp/batch-is-authorized endpoints.
//! Uses the test policy set in pdp/policies/ (not the production set in ../policies/).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

/// Start a test server with AVP endpoints registered.
/// Uses pdp/policies/ which has a simplified schema:
///   - User in [Role] { email: String, department?: String }
///   - Role (no attrs)
///   - ApiResource (no attrs)
///   - Actions: read, write, delete
///   - Policies: admin-full-access, viewer-read-only, alice-view
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

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

/// Build an AVP entity set for alice (admin role) with entities matching
/// the test schema (User has email, Role has no attrs, ApiResource has no attrs).
fn alice_admin_entities(resource_id: &str) -> Value {
    json!({
        "entityList": [
            {
                "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                "Attributes": {
                    "email": { "String": "alice@example.com" },
                    "department": { "String": "engineering" }
                },
                "Parents": [
                    { "EntityType": "ApiGateway::Role", "EntityId": "admin" }
                ]
            },
            {
                "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" },
                "Attributes": {},
                "Parents": []
            },
            {
                "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": resource_id },
                "Attributes": {},
                "Parents": []
            }
        ]
    })
}

/// Build an AVP entity set for a viewer user.
fn viewer_entities(user_id: &str, resource_id: &str) -> Value {
    json!({
        "entityList": [
            {
                "Identifier": { "EntityType": "ApiGateway::User", "EntityId": user_id },
                "Attributes": {
                    "email": { "String": format!("{user_id}@example.com") }
                },
                "Parents": [
                    { "EntityType": "ApiGateway::Role", "EntityId": "viewer" }
                ]
            },
            {
                "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "viewer" },
                "Attributes": {},
                "Parents": []
            },
            {
                "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": resource_id },
                "Attributes": {},
                "Parents": []
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Single authorization tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_single_allow_admin_read() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/v1/users" },
            "entities": alice_admin_entities("/api/v1/users")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "ALLOW");
    assert!(!body["determiningPolicies"].as_array().unwrap().is_empty());
    assert!(body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_single_allow_admin_write() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "entities": alice_admin_entities("/api/data")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "ALLOW");
}

#[tokio::test]
async fn avp_single_deny_no_matching_policies() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Unknown user with no role -- no policy matches.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "nobody" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "entities": {
                "entityList": [
                    {
                        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "nobody" },
                        "Attributes": { "email": { "String": "nobody@example.com" } },
                        "Parents": []
                    },
                    {
                        "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/api/data" },
                        "Attributes": {},
                        "Parents": []
                    }
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "DENY");
    assert!(body["determiningPolicies"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_single_deny_viewer_cannot_write() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Viewer trying to write -- viewer-read-only only allows read.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "bob" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "entities": viewer_entities("bob", "/api/data")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "DENY");
}

#[tokio::test]
async fn avp_single_allow_viewer_read() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "bob" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "entities": viewer_entities("bob", "/api/data")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "ALLOW");
}

#[tokio::test]
async fn avp_single_empty_entities() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // No entities provided -- evaluation proceeds with empty entity set, should DENY.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "ghost" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // alice-view policy matches principal == alice only, not ghost.
    // No role membership without entities, so no RBAC match either.
    assert_eq!(body["decision"], "DENY");
}

#[tokio::test]
async fn avp_single_with_context() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Context with typed values. The test schema doesn't declare context
    // fields on any action, so extra context keys cause a request validation
    // error in Cedar (fail-closed: DENY with error). This test verifies the
    // context parsing pipeline works and produces a clean error, not a crash.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "context": {
                "contextMap": {
                    "ip": { "String": "192.168.1.1" },
                    "authenticated": { "Boolean": true },
                    "retryCount": { "Long": 0 }
                }
            },
            "entities": alice_admin_entities("/api/data")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // DENY because the schema doesn't declare context for this action.
    // This validates context parsing works (typed values parsed without error)
    // and the schema validation correctly rejects unknown context keys.
    assert_eq!(body["decision"], "DENY");
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_single_policy_store_id_accepted() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // policyStoreId should be accepted and ignored.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "policyStoreId": "PSexample123456789",
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "entities": alice_admin_entities("/api/data")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "ALLOW");
}

#[tokio::test]
async fn avp_single_response_format() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" },
            "entities": alice_admin_entities("/api/data")
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // Verify AVP response shape.
    assert!(body["decision"] == "ALLOW" || body["decision"] == "DENY");
    assert!(body["determiningPolicies"].is_array());
    assert!(body["errors"].is_array());

    // determiningPolicies items must have policyId field.
    for policy in body["determiningPolicies"].as_array().unwrap() {
        assert!(policy["policyId"].is_string());
    }

    // Verify camelCase (not snake_case).
    assert!(body.get("determining_policies").is_none());
    assert!(body.get("error_description").is_none());
}

#[tokio::test]
async fn avp_single_malformed_typed_value() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Entity with an invalid typed value wrapper.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" },
            "entities": {
                "entityList": [
                    {
                        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                        "Attributes": {
                            "email": { "Float": 3.14 }
                        },
                        "Parents": []
                    }
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Malformed entity -> fail-closed DENY with error.
    assert_eq!(body["decision"], "DENY");
    assert!(!body["errors"].as_array().unwrap().is_empty());
    let err = body["errors"][0]["errorDescription"].as_str().unwrap();
    assert!(err.contains("unrecognized AVP typed value"));
}

// ---------------------------------------------------------------------------
// Batch authorization tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_batch_mixed_decisions() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Same principal (alice/admin), different actions. read=ALLOW, delete=ALLOW (admin has full access).
    // Add a second principal (bob/viewer) with same resource to test DENY.
    // Use same-resource pattern so both principals can be in one batch.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "entities": {
                "entityList": [
                    {
                        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                        "Attributes": { "email": { "String": "alice@example.com" } },
                        "Parents": [{ "EntityType": "ApiGateway::Role", "EntityId": "admin" }]
                    },
                    {
                        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "bob" },
                        "Attributes": { "email": { "String": "bob@example.com" } },
                        "Parents": [{ "EntityType": "ApiGateway::Role", "EntityId": "viewer" }]
                    },
                    { "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" }, "Attributes": {}, "Parents": [] },
                    { "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "viewer" }, "Attributes": {}, "Parents": [] },
                    { "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/data" }, "Attributes": {}, "Parents": [] }
                ]
            },
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
                },
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "bob" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);

    // alice (admin) can write.
    assert_eq!(results[0]["decision"], "ALLOW");
    // bob (viewer) cannot write.
    assert_eq!(results[1]["decision"], "DENY");
}

#[tokio::test]
async fn avp_batch_empty_requests() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({ "requests": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["results"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_batch_exceeds_limit() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let item = json!({
        "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
        "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
        "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
    });
    let requests: Vec<Value> = (0..31).map(|_| item.clone()).collect();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({ "requests": requests }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("30"));
}

#[tokio::test]
async fn avp_batch_homogeneity_violation() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Different principals AND different resources -- fails validation.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data1" }
                },
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "bob" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data2" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("same principal or the same resource"));
}

#[tokio::test]
async fn avp_batch_same_principal_valid() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    // Same principal, different resources -- valid batch.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "entities": {
                "entityList": [
                    {
                        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                        "Attributes": { "email": { "String": "alice@example.com" } },
                        "Parents": [{ "EntityType": "ApiGateway::Role", "EntityId": "admin" }]
                    },
                    { "Identifier": { "EntityType": "ApiGateway::Role", "EntityId": "admin" }, "Attributes": {}, "Parents": [] },
                    { "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/a" }, "Attributes": {}, "Parents": [] },
                    { "Identifier": { "EntityType": "ApiGateway::ApiResource", "EntityId": "/b" }, "Attributes": {}, "Parents": [] }
                ]
            },
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/a" }
                },
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/b" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    // Admin can do both.
    assert_eq!(results[0]["decision"], "ALLOW");
    assert_eq!(results[1]["decision"], "ALLOW");
}

#[tokio::test]
async fn avp_batch_response_echoes_request() {
    let addr = start_avp_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/api/data" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let result = &body["results"][0];

    // Verify the request echo matches.
    assert_eq!(result["request"]["principal"]["entityType"], "ApiGateway::User");
    assert_eq!(result["request"]["principal"]["entityId"], "alice");
    assert_eq!(result["request"]["action"]["actionType"], "ApiGateway::Action");
    assert_eq!(result["request"]["action"]["actionId"], "write");
    assert_eq!(result["request"]["resource"]["entityType"], "ApiGateway::ApiResource");
    assert_eq!(result["request"]["resource"]["entityId"], "/api/data");
}
