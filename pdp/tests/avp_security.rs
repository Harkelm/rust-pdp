//! Adversarial and security tests for the AVP endpoints.
//!
//! Covers error paths, malformed inputs, constraint violations, and boundary
//! conditions for /avp/is-authorized and /avp/batch-is-authorized.
//!
//! The PDP is fail-closed: every error path must produce DENY, never crash,
//! and never produce ALLOW as a fallback.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

async fn start_server() -> SocketAddr {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
    let store = cedar_pdp::policy::PolicyStore::from_dir(&policy_path).expect("load policies");
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
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------------
// Empty and non-JSON bodies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_empty_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "empty body must return 400");
}

#[tokio::test]
async fn avp_empty_json_object_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // {} is valid JSON but missing required fields principal/action/resource.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        422,
        "empty JSON object must be rejected with 422 (missing required fields)"
    );
}

#[tokio::test]
async fn avp_non_json_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .header("content-type", "application/json")
        .body("this is not json at all")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "non-JSON body must return 400");
}

#[tokio::test]
async fn avp_truncated_json_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Truncated mid-object -- incomplete JSON.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .header("content-type", "application/json")
        .body(r#"{"principal": {"entityType": "ApiGateway::User""#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "truncated JSON must return 400");
}

// ---------------------------------------------------------------------------
// Missing required fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_missing_principal_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422, "missing principal must be rejected");
}

#[tokio::test]
async fn avp_missing_action_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422, "missing action must be rejected");
}

#[tokio::test]
async fn avp_missing_resource_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422, "missing resource must be rejected");
}

// ---------------------------------------------------------------------------
// Malformed typed value wrappers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_string_value_with_integer_payload_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "email": { "String": 123 } },
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
    assert_eq!(
        body["decision"], "DENY",
        "String wrapper with integer payload must fail closed to DENY"
    );
    assert!(
        !body["errors"].as_array().unwrap().is_empty(),
        "errors array must describe the malformed typed value"
    );
}

#[tokio::test]
async fn avp_boolean_value_with_string_payload_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "active": { "Boolean": "yes" } },
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
    assert_eq!(
        body["decision"], "DENY",
        "Boolean wrapper with string payload must fail closed to DENY"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_long_value_with_string_payload_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "count": { "Long": "42" } },
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
    assert_eq!(
        body["decision"], "DENY",
        "Long wrapper with string payload must fail closed to DENY"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_unknown_typed_value_wrapper_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "score": { "Float": 9.5 } },
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
    assert_eq!(
        body["decision"], "DENY",
        "unrecognized typed value wrapper must fail closed to DENY"
    );
    let err_desc = body["errors"][0]["errorDescription"].as_str().unwrap();
    assert!(
        err_desc.contains("unrecognized AVP typed value"),
        "error description must name the problem, got: {err_desc}"
    );
}

#[tokio::test]
async fn avp_set_with_non_array_payload_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "roles": { "Set": "not-an-array" } },
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
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_record_with_non_object_payload_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "meta": { "Record": [1, 2, 3] } },
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
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Truncated/malformed EntityIdentifier in principal or resource
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_principal_missing_entity_type_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // entityType is required on AvpEntityRef -- missing it is a 422.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        422,
        "principal missing entityType must be rejected with 422"
    );
}

#[tokio::test]
async fn avp_principal_missing_entity_id_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        422,
        "principal missing entityId must be rejected with 422"
    );
}

#[tokio::test]
async fn avp_principal_invalid_cedar_type_name_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Entity type names must be valid Cedar identifiers (no spaces, valid chars).
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "not a valid::type name!!!", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "DENY",
        "invalid entity type name must fail closed to DENY, not crash"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_action_missing_action_type_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        422,
        "action missing actionType must be rejected with 422"
    );
}

#[tokio::test]
async fn avp_entity_identifier_attribute_missing_type_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // EntityIdentifier wrapper without EntityType field.
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
                            "ref": { "EntityIdentifier": { "EntityId": "doc-1" } }
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
    assert_eq!(
        body["decision"], "DENY",
        "EntityIdentifier missing EntityType must fail closed to DENY"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_entity_identifier_attribute_missing_id_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // EntityIdentifier wrapper without EntityId field.
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
                            "ref": { "EntityIdentifier": { "EntityType": "ApiGateway::ApiResource" } }
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
    assert_eq!(
        body["decision"], "DENY",
        "EntityIdentifier missing EntityId must fail closed to DENY"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Deeply nested typed values
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_deeply_nested_set_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Build a 40-level deep Set nesting (exceeds MAX_TYPED_VALUE_DEPTH=32).
    let mut nested: Value = json!({ "String": "leaf" });
    for _ in 0..40 {
        nested = json!({ "Set": [nested] });
    }

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
                        "Attributes": { "deep": nested },
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
    assert_eq!(
        body["decision"], "DENY",
        "deeply nested typed value must fail closed to DENY (depth limit exceeded)"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_deeply_nested_record_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Build a 40-level deep Record nesting.
    let mut nested: Value = json!({ "String": "leaf" });
    for _ in 0..40 {
        nested = json!({ "Record": { "inner": nested } });
    }

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
                        "Attributes": { "deep": nested },
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
    assert_eq!(
        body["decision"], "DENY",
        "deeply nested Record must fail closed to DENY (depth limit exceeded)"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Null bytes and very long strings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_null_byte_in_entity_id_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Null bytes are valid in JSON strings. Must not crash.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice\0injected" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    // Null bytes in entity IDs are valid Cedar (EntityId::new accepts any string).
    // The request will evaluate -- it will DENY because no policy matches this ID.
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_ne!(
        body["decision"], "ALLOW",
        "null byte in entity ID must never produce spurious ALLOW"
    );
}

#[tokio::test]
async fn avp_null_byte_in_string_attribute_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

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
                        "Attributes": { "email": { "String": "user\0@example.com" } },
                        "Parents": []
                    }
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    // Must not crash. DENY is expected (schema validation will reject).
    // Must not crash. Decision depends on whether the attribute value passes schema
    // validation -- the point is that null bytes don't cause a panic.
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["decision"] == "ALLOW" || body["decision"] == "DENY",
        "must return a valid decision, got {:?}",
        body["decision"]
    );
}

#[tokio::test]
async fn avp_very_long_entity_id_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let long_id = "x".repeat(10_000);
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": long_id },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "DENY", "very long entity ID must not match any policy");
}

#[tokio::test]
async fn avp_very_long_string_attribute_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let long_email = format!("{}@example.com", "a".repeat(10_000));
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
                        "Attributes": { "email": { "String": long_email } },
                        "Parents": []
                    }
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    // Must not crash or hang. Long attribute values are valid -- decision depends
    // on whether the entity matches a policy.
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["decision"] == "ALLOW" || body["decision"] == "DENY",
        "must return a valid decision, got {:?}",
        body["decision"]
    );
}

// ---------------------------------------------------------------------------
// Unknown/extra fields in request body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_extra_fields_in_request_are_ignored() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Serde unknown field behavior: serde_json ignores unknown fields by default
    // unless #[serde(deny_unknown_fields)] is set. Verify the server does not crash.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "nobody" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" },
            "unexpectedField": "attacker-controlled-value",
            "anotherExtraField": { "nested": true },
            "__proto__": { "isAdmin": true }
        }))
        .send()
        .await
        .unwrap();

    // Must accept the request (or return 422 if deny_unknown_fields), never crash.
    assert!(
        resp.status() == 200 || resp.status() == 422,
        "extra fields must produce 200 (ignored) or 422 (rejected), got {}",
        resp.status()
    );
    if resp.status() == 200 {
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["decision"], "DENY", "unknown principal must fail closed to DENY");
    }
}

#[tokio::test]
async fn avp_extra_fields_in_entity_are_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Extra fields on an entity object (outside Attributes).
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
                        "Attributes": { "email": { "String": "alice@example.com" } },
                        "Parents": [],
                        "unknownEntityField": "ignored?"
                    }
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    assert!(
        resp.status() == 200 || resp.status() == 422,
        "extra entity fields must not crash, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Batch endpoint: structural violations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_batch_empty_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "empty batch body must return 400");
}

#[tokio::test]
async fn avp_batch_non_json_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "non-JSON batch body must return 400");
}

#[tokio::test]
async fn avp_batch_missing_requests_field_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // `requests` is required on AvpBatchIsAuthorizedRequest.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({ "entities": null }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        422,
        "batch request missing `requests` field must be rejected with 422"
    );
}

#[tokio::test]
async fn avp_batch_requests_not_array_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({ "requests": "not-an-array" }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        422,
        "batch requests field must be an array"
    );
}

#[tokio::test]
async fn avp_batch_exceeds_limit_of_30_returns_400() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // 31 items with same principal (valid homogeneity) -- exceeds the 30 item cap.
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

    assert_eq!(
        resp.status(),
        400,
        "batch exceeding 30 items must return 400"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("30"),
        "error message must mention the limit"
    );
}

#[tokio::test]
async fn avp_batch_exactly_at_limit_of_30_accepted() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Exactly 30 items with same principal -- must be accepted.
    let item = json!({
        "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
        "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
        "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
    });
    let requests: Vec<Value> = (0..30).map(|_| item.clone()).collect();

    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({ "requests": requests }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "exactly 30 items must be accepted"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["results"].as_array().unwrap().len(),
        30,
        "must return exactly 30 results"
    );
}

// ---------------------------------------------------------------------------
// Batch endpoint: homogeneity constraint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_batch_homogeneity_violation_returns_400() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Different principals AND different resources -- explicit homogeneity failure.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/a" }
                },
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "bob" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/b" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "homogeneity violation must return 400"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("same principal or the same resource"),
        "error must describe the homogeneity constraint"
    );
}

#[tokio::test]
async fn avp_batch_homogeneity_adversarial_three_way_mixed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Three items: first two share principal, third has different principal and resource.
    // This violates the constraint because the overall batch does not have uniform
    // principal OR uniform resource.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
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
                },
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "charlie" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/c" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "three-way mixed homogeneity must return 400"
    );
}

#[tokio::test]
async fn avp_batch_homogeneity_adversarial_type_mismatch() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Same entityId but different entityType -- must not satisfy homogeneity.
    // "alice" as User != "alice" as AdminUser.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/a" }
                },
                {
                    "principal": { "entityType": "ApiGateway::AdminUser", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/b" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    // Different entity types with same id are not the same principal.
    assert_eq!(
        resp.status(),
        400,
        "principals differing by entityType must violate homogeneity"
    );
}

// ---------------------------------------------------------------------------
// Batch endpoint: fail-closed semantics for malformed items
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_batch_malformed_entity_set_denies_all_items() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Shared entity set has a malformed typed value. All items in the batch
    // must DENY -- the entity build failure propagates to every result.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "entities": {
                "entityList": [
                    {
                        "Identifier": { "EntityType": "ApiGateway::User", "EntityId": "alice" },
                        "Attributes": { "email": { "Float": 3.14 } },
                        "Parents": []
                    }
                ]
            },
            "requests": [
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
                },
                {
                    "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "write" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/other" }
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
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result["decision"], "DENY",
            "batch item {i} must DENY when shared entity set is malformed"
        );
        assert!(
            !result["errors"].as_array().unwrap().is_empty(),
            "batch item {i} must include error description"
        );
    }
}

#[tokio::test]
async fn avp_batch_invalid_principal_type_in_item_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Batch with same resource (valid homogeneity), but one item has an
    // unparseable entity type name in the principal.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "requests": [
                {
                    "principal": { "entityType": "!!invalid!!", "entityId": "alice" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
                },
                {
                    "principal": { "entityType": "!!invalid!!", "entityId": "bob" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
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
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result["decision"], "DENY",
            "batch item {i} with invalid principal type must DENY"
        );
    }
}

// ---------------------------------------------------------------------------
// Context malformed values
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_context_malformed_typed_value_fails_closed() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Context with an unrecognized wrapper in a value.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" },
            "context": {
                "contextMap": {
                    "ip": { "IPv4": "10.0.0.1" }
                }
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "DENY",
        "unrecognized context typed value must fail closed to DENY"
    );
    assert!(!body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn avp_context_map_as_non_object_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // contextMap must be an object, not an array.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "ApiGateway::User", "entityId": "alice" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" },
            "context": {
                "contextMap": ["not", "an", "object"]
            }
        }))
        .send()
        .await
        .unwrap();

    assert!(
        resp.status() == 422 || resp.status() == 200,
        "non-object contextMap must return 422 or a DENY response, got {}",
        resp.status()
    );
    if resp.status() == 200 {
        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["decision"], "DENY",
            "non-object contextMap must fail closed to DENY if parsed"
        );
    }
}

// ---------------------------------------------------------------------------
// Response shape invariants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avp_single_response_always_has_required_fields() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Even for an invalid entity type, the response shape must be complete.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&json!({
            "principal": { "entityType": "!!bad!!", "entityId": "x" },
            "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
            "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // Required AVP response fields must always be present.
    assert!(body["decision"].is_string(), "decision must be a string");
    assert!(
        body["determiningPolicies"].is_array(),
        "determiningPolicies must be an array"
    );
    assert!(body["errors"].is_array(), "errors must be an array");

    // snake_case variants must NOT appear.
    assert!(body.get("determining_policies").is_none());
    assert!(body.get("error_description").is_none());
}

#[tokio::test]
async fn avp_batch_response_always_has_required_fields() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Batch with a malformed principal -- results must still be well-formed.
    let resp = client
        .post(format!("http://{addr}/avp/batch-is-authorized"))
        .json(&json!({
            "requests": [
                {
                    "principal": { "entityType": "!!bad!!", "entityId": "x" },
                    "action": { "actionType": "ApiGateway::Action", "actionId": "read" },
                    "resource": { "entityType": "ApiGateway::ApiResource", "entityId": "/data" }
                },
                {
                    "principal": { "entityType": "!!bad!!", "entityId": "y" },
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

    for (i, result) in results.iter().enumerate() {
        assert!(result["decision"].is_string(), "result {i}: decision must be a string");
        assert!(result["determiningPolicies"].is_array(), "result {i}: determiningPolicies must be an array");
        assert!(result["errors"].is_array(), "result {i}: errors must be an array");
        assert!(result["request"].is_object(), "result {i}: request echo must be present");
        assert_eq!(result["decision"], "DENY", "result {i}: malformed principal must DENY");
    }
}
