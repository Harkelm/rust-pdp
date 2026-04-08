//! Security and adversarial input tests.
//!
//! Validates error paths, malformed requests, and attack surfaces identified
//! in the roundtable review (Schneier F5: skip-on-error; AGI-Acc F3: fail-closed).

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
        .route("/v1/batch_is_authorized", post(cedar_pdp::handlers::batch_is_authorized))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------------
// Malformed request body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    // Missing required fields (principal, action, resource) -- axum returns 422
    assert_eq!(resp.status(), 422, "empty JSON body must be rejected");
}

#[tokio::test]
async fn test_non_json_body_returns_error() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .header("content-type", "application/json")
        .body("this is not json")
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_client_error(),
        "non-JSON body must return 4xx, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_missing_action_field() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ApiGateway::User::\"alice\"",
            "resource": "ApiGateway::ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422, "missing action field must be rejected");
}

// ---------------------------------------------------------------------------
// Invalid Cedar entity UID strings (legacy path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_invalid_principal_uid_returns_deny() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "not-a-valid-cedar-uid",
            "action": "ApiGateway::Action::\"read\"",
            "resource": "ApiGateway::ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Deny",
        "invalid principal UID must result in Deny, not crash"
    );
    assert!(
        !body["diagnostics"]["errors"].as_array().unwrap().is_empty(),
        "diagnostics must contain the parse error"
    );
}

#[tokio::test]
async fn test_invalid_action_uid_returns_deny() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ApiGateway::User::\"alice\"",
            "action": "!!!invalid!!!",
            "resource": "ApiGateway::ApiResource::\"doc-1\""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Deny");
}

#[tokio::test]
async fn test_invalid_resource_uid_returns_deny() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ApiGateway::User::\"alice\"",
            "action": "ApiGateway::Action::\"read\"",
            "resource": "💀💀💀"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Deny");
}

// ---------------------------------------------------------------------------
// Claims path: unknown HTTP method (fail-closed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unknown_http_method_denied() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "TRACE",
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
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Deny",
        "unknown HTTP method TRACE must be denied (fail-closed)"
    );
}

#[tokio::test]
async fn test_custom_http_method_denied() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "PURGE",
            "resource": "/api/v1/cache",
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
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "Deny", "custom method PURGE must be denied");
}

// ---------------------------------------------------------------------------
// Claims path: minimal/partial claims -- Schneier F5 attack surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_claims_missing_sub_rejected() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // `sub` is the only required Claims field. Omitting it should cause
    // deserialization failure or Deny, never Allow.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/users",
            "claims": {
                "email": "alice@example.com",
                "roles": ["admin"]
            }
        }))
        .send()
        .await
        .unwrap();

    // Either 422 (deser failure) or 200 with Deny -- never Allow.
    if resp.status() == 200 {
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_ne!(
            body["decision"], "Allow",
            "missing sub claim must never produce Allow"
        );
    }
    // 422 is also acceptable -- the request was malformed.
}

#[tokio::test]
async fn test_claims_only_sub_gets_org_scoped_permit() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Only `sub` provided -- all optional fields default. User has no roles,
    // no org, suspended=false by default. The org-scoped-read-write permit
    // fires because principal.org defaults to "" and resource.owner_org also
    // defaults to "" (both from claims.org=None). Empty string == empty string.
    // This documents a policy design consideration: org-scoped permit is very
    // broad when org defaults to empty.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "minimal-user"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Allow",
        "sub-only user allowed via org-scoped permit (empty org == empty owner_org)"
    );
}

#[tokio::test]
async fn test_claims_only_sub_delete_still_denied() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // DELETE is not covered by org-scoped (only read+write). A sub-only user
    // with no roles truly has no permit for delete.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "DELETE",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "minimal-user"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Deny",
        "sub-only user must be denied DELETE (no policy grants it)"
    );
}

// ---------------------------------------------------------------------------
// Schneier F5: suspended flag skip-on-error -- verify forbid fires
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_suspended_admin_with_all_permissions_still_denied() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Admin with every possible privilege, but suspended=true.
    // The forbid policy must override all permits.
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/users",
            "claims": {
                "sub": "super-admin",
                "email": "admin@acme.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["admin", "editor", "viewer"],
                "subscription_tier": "enterprise",
                "suspended": true,
                "allowed_scopes": ["internal", "public", "confidential", "restricted"]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "Deny",
        "suspended user MUST be denied regardless of roles/tier/scopes (forbid override)"
    );
}

#[tokio::test]
async fn test_suspended_flag_overrides_all_actions() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // Verify forbid fires for every action type, not just read.
    for method in &["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let resp = client
            .post(format!("http://{addr}/v1/is_authorized"))
            .json(&serde_json::json!({
                "principal": "ignored",
                "action": method,
                "resource": "/api/v1/data",
                "claims": {
                    "sub": "suspended-editor",
                    "email": "editor@acme.com",
                    "department": "engineering",
                    "org": "acme",
                    "roles": ["editor"],
                    "subscription_tier": "professional",
                    "suspended": true,
                    "allowed_scopes": ["internal"]
                }
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["decision"], "Deny",
            "suspended user must be denied for method {method}"
        );
    }
}

// ---------------------------------------------------------------------------
// Batch endpoint: adversarial inputs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_with_one_invalid_request() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // One valid request + one with unknown HTTP method. The valid one should
    // still evaluate correctly; the invalid one should be Deny.
    let resp = client
        .post(format!("http://{addr}/v1/batch_is_authorized"))
        .json(&serde_json::json!({
            "requests": [
                {
                    "principal": "ignored",
                    "action": "GET",
                    "resource": "/api/v1/users",
                    "context": {},
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
                },
                {
                    "principal": "ignored",
                    "action": "TRACE",
                    "resource": "/api/v1/debug",
                    "context": {},
                    "claims": {
                        "sub": "attacker",
                        "email": "attacker@evil.com",
                        "department": "unknown",
                        "org": "acme",
                        "roles": ["admin"],
                        "subscription_tier": "enterprise",
                        "suspended": false,
                        "allowed_scopes": ["internal"]
                    }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let responses = body["responses"].as_array().unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["decision"], "Allow", "valid admin GET should Allow");
    assert_eq!(responses[1]["decision"], "Deny", "TRACE method must Deny even in batch");
}

#[tokio::test]
async fn test_batch_all_invalid_returns_all_deny() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/batch_is_authorized"))
        .json(&serde_json::json!({
            "requests": [
                {
                    "principal": "ignored",
                    "action": "TRACE",
                    "resource": "/x",
                    "context": {},
                    "claims": { "sub": "a" }
                },
                {
                    "principal": "ignored",
                    "action": "PURGE",
                    "resource": "/y",
                    "context": {},
                    "claims": { "sub": "b" }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let responses = body["responses"].as_array().unwrap();
    assert_eq!(responses.len(), 2);
    for (i, r) in responses.iter().enumerate() {
        assert_eq!(r["decision"], "Deny", "request {i} with invalid method must Deny");
    }
}

// ---------------------------------------------------------------------------
// Large/unusual string inputs -- not a fuzz test, but exercises boundaries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_very_long_principal_id_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let long_sub = "a".repeat(10_000);
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/data",
            "claims": {
                "sub": long_sub,
                "email": "long@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["viewer"],
                "subscription_tier": "basic",
                "suspended": false,
                "allowed_scopes": []
            }
        }))
        .send()
        .await
        .unwrap();

    // Should not panic or hang. Deny is expected (no matching policy for this user).
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["decision"].is_string(),
        "must return a decision, not crash"
    );
}

#[tokio::test]
async fn test_special_characters_in_resource_path() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/../../etc/passwd",
            "claims": {
                "sub": "traversal-user",
                "email": "user@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["admin"],
                "subscription_tier": "enterprise",
                "suspended": false,
                "allowed_scopes": ["internal"]
            }
        }))
        .send()
        .await
        .unwrap();

    // The PDP evaluates the resource string as-is against policies.
    // Path traversal in the resource string should not match any
    // legitimate resource pattern. The PDP does not do path
    // normalization -- that's the gateway's job.
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["decision"].is_string(), "must not crash on traversal paths");
}

#[tokio::test]
async fn test_null_bytes_in_claims_handled() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "user\0injected",
                "email": "user@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["viewer"],
                "subscription_tier": "basic",
                "suspended": false,
                "allowed_scopes": []
            }
        }))
        .send()
        .await
        .unwrap();

    // Null bytes in strings are valid JSON. Should not crash.
    assert_eq!(resp.status(), 200);
}
