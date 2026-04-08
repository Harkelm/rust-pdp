//! Diagnostics and determining-policy verification tests.
//!
//! These tests verify not just the decision (Allow/Deny) but the structure
//! of Cedar's diagnostics response: how many policies determined the outcome,
//! whether errors are present, and whether the diagnostics contain actionable
//! information for debugging.
//!
//! Critical for:
//! - Production debugging ("why was this request denied?")
//! - Policy auditing ("how many independent permits grant this access?")
//! - Regression detection ("did a policy change reduce redundant permits?")
//!
//! Note: Cedar returns auto-generated policy IDs (policy0, policy1, ...) when
//! policies are parsed from concatenated source. The @id("...") annotations
//! are stored as Cedar annotations but not reflected in PolicyId::to_string().
//! Tests use structural assertions (counts, presence) rather than exact names.

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
    let state: cedar_pdp::handlers::AppState =
        Arc::new(cedar_pdp::handlers::AppContext::new(store, None));

    let app = Router::new()
        .route("/v1/is_authorized", post(cedar_pdp::handlers::is_authorized))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Helper: make an authz request and return (decision, reason_policies, errors).
async fn authz_full(
    addr: SocketAddr,
    action: &str,
    resource: &str,
    claims: serde_json::Value,
) -> (String, Vec<String>, Vec<String>) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": action,
            "resource": resource,
            "claims": claims
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let decision = body["decision"].as_str().unwrap().to_string();
    let reasons: Vec<String> = body["diagnostics"]["reason"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let errors: Vec<String> = body["diagnostics"]["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    (decision, reasons, errors)
}

fn admin_claims() -> serde_json::Value {
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

fn viewer_claims() -> serde_json::Value {
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

// ===========================================================================
// Determining policies for Allow decisions
// ===========================================================================

#[tokio::test]
async fn test_admin_read_determining_policies() {
    let addr = start_server().await;
    let (decision, reasons, errors) = authz_full(addr, "GET", "/api/v1/data", admin_claims()).await;

    assert_eq!(decision, "Allow");
    assert!(errors.is_empty(), "no evaluation errors expected");

    // Admin GET should be granted by multiple independent policies:
    // - rbac-admin-all (admin role permits all actions)
    // - org-scoped-read-write (principal.org == resource.owner_org for read/write)
    // - data-scope-read (principal.allowed_scopes contains resource.classification)
    // Cedar returns auto-generated IDs, so we check count rather than names.
    assert!(
        reasons.len() >= 3,
        "admin GET should fire at least 3 independent permits \
         (RBAC + org-scoped + data-scope), got {}: {reasons:?}",
        reasons.len()
    );
}

#[tokio::test]
async fn test_viewer_read_determining_policies() {
    let addr = start_server().await;
    let (decision, reasons, _) = authz_full(addr, "GET", "/api/v1/data", viewer_claims()).await;

    assert_eq!(decision, "Allow");
    // Viewer GET: rbac-viewer-read + org-scoped-read-write should both fire.
    // data-scope-read should NOT fire (viewer has allowed_scopes=["public"],
    // resource.classification defaults to "internal").
    // Expect exactly 2 determining policies.
    assert_eq!(
        reasons.len(), 2,
        "viewer GET should fire exactly 2 permits (RBAC viewer + org-scoped), got: {reasons:?}"
    );
}

#[tokio::test]
async fn test_editor_write_determining_policies() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "diag-editor",
        "email": "editor@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["editor"],
        "subscription_tier": "professional",
        "suspended": false,
        "allowed_scopes": ["internal"]
    });
    let (decision, reasons, _) = authz_full(addr, "POST", "/api/v1/data", claims).await;

    assert_eq!(decision, "Allow");
    // Editor POST (write): rbac-editor-rw + org-scoped-read-write should both fire.
    // Expect exactly 2 determining policies.
    assert_eq!(
        reasons.len(), 2,
        "editor POST should fire exactly 2 permits (RBAC editor + org-scoped), got: {reasons:?}"
    );
}

// ===========================================================================
// Determining policies for Deny decisions
// ===========================================================================

#[tokio::test]
async fn test_deny_has_empty_reason_set() {
    let addr = start_server().await;
    // Viewer DELETE: no policy grants delete to viewer. Deny should have empty reasons.
    let (decision, reasons, errors) = authz_full(addr, "DELETE", "/api/v1/data", viewer_claims()).await;

    assert_eq!(decision, "Deny");
    assert!(
        reasons.is_empty(),
        "deny due to no matching permit should have empty reasons, got: {reasons:?}"
    );
    assert!(
        errors.is_empty(),
        "clean deny should have no evaluation errors, got: {errors:?}"
    );
}

#[tokio::test]
async fn test_suspended_deny_shows_forbid_policy() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "diag-suspended",
        "email": "sus@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["admin"],
        "subscription_tier": "enterprise",
        "suspended": true,
        "allowed_scopes": ["internal"]
    });
    let (decision, reasons, _) = authz_full(addr, "GET", "/api/v1/data", claims).await;

    assert_eq!(decision, "Deny");
    // Cedar forbid policies appear in diagnostics.reason when they determine
    // the outcome. The suspended-account-deny forbid should be listed.
    // Cedar uses auto-generated IDs, so we check that at least one determining
    // policy exists (the forbid that fired).
    assert!(
        !reasons.is_empty(),
        "suspended deny must show at least one determining policy (the forbid), got: {reasons:?}"
    );
}

// ===========================================================================
// Error diagnostics for malformed requests
// ===========================================================================

#[tokio::test]
async fn test_unknown_method_deny_has_error_diagnostic() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "diag-trace",
        "email": "trace@acme.com",
        "department": "engineering",
        "org": "acme",
        "roles": ["admin"],
        "subscription_tier": "enterprise",
        "suspended": false,
        "allowed_scopes": ["internal"]
    });
    let (decision, _reasons, errors) = authz_full(addr, "TRACE", "/api/v1/data", claims).await;

    assert_eq!(decision, "Deny");
    // Unknown method should produce an error in diagnostics explaining why
    assert!(
        !errors.is_empty(),
        "unknown method deny should include an error diagnostic explaining the rejection"
    );
}

// ===========================================================================
// Policy count verification: how many policies fire for common scenarios
// ===========================================================================

/// Verify the redundancy property: admin read fires 3+ independent permits.
/// This documents that removing any single policy won't break admin access --
/// important for understanding blast radius of policy changes.
#[tokio::test]
async fn test_admin_has_redundant_authorization_paths() {
    let addr = start_server().await;
    let (decision, reasons, _) = authz_full(addr, "GET", "/api/v1/data", admin_claims()).await;
    assert_eq!(decision, "Allow");

    assert!(
        reasons.len() >= 3,
        "admin read should fire at least 3 independent permits (RBAC + org-scoped + data-scope), \
         got {} policies: {reasons:?}",
        reasons.len()
    );

    // Compare with admin DELETE: only RBAC grants delete (org-scoped doesn't cover delete)
    let (del_decision, del_reasons, _) = authz_full(addr, "DELETE", "/api/v1/data", admin_claims()).await;
    assert_eq!(del_decision, "Allow");
    assert!(
        del_reasons.len() < reasons.len(),
        "admin DELETE should have fewer determining policies than GET \
         (org-scoped only covers read+write, not delete). \
         GET: {} policies, DELETE: {} policies",
        reasons.len(), del_reasons.len()
    );
}

#[tokio::test]
async fn test_roleless_same_org_user_determining_policy() {
    let addr = start_server().await;
    let claims = serde_json::json!({
        "sub": "diag-roleless",
        "email": "nobody@acme.com",
        "department": "unknown",
        "org": "acme",
        "roles": [],
        "subscription_tier": "basic",
        "suspended": false,
        "allowed_scopes": []
    });
    let (decision, reasons, _) = authz_full(addr, "GET", "/api/v1/data", claims).await;

    assert_eq!(decision, "Allow");
    // A roleless user with matching org should ONLY be granted by org-scoped.
    // No RBAC policy should fire (no roles). No data-scope (empty scopes).
    // Expect exactly 1 determining policy (org-scoped-read-write).
    assert_eq!(
        reasons.len(), 1,
        "roleless same-org user should have exactly 1 determining policy (org-scoped), got: {reasons:?}"
    );
}
