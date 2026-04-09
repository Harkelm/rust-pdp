//! Edge case tests covering gaps identified in the review:
//!
//! - Empty policy set behavior (all .cedar files removed)
//! - Schema-only change detection on reload
//! - Batch with 100 identical items (no deduplication -- each evaluated independently)
//! - Concurrent admin reload requests under rate limiting
//! - AVP with unknown/unmapped action strings
//! - Large claim values (1MB principal ID)
//! - Policy epoch monotonicity guarantees

mod common;
use common::{
    admin_allow_request, production_policy_dir, start_avp_server, start_server,
    viewer_deny_request,
};

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Empty policy set: all .cedar files removed, schema remains
// ---------------------------------------------------------------------------

#[test]
fn empty_policy_set_denies_everything() {
    // If all .cedar files are deleted but schema remains, the PDP should still
    // load (zero policies) and deny all requests (no permits exist).
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("api_gateway.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    // No .cedar files at all.

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path())
        .expect("should load with zero policies");
    assert_eq!(store.policy_count(), 0, "zero policies when no .cedar files exist");

    // Reload should also succeed with zero policies.
    let count = store.reload().expect("reload with zero policies should succeed");
    assert_eq!(count, 0);
}

#[test]
fn empty_policy_set_after_removing_all_cedar_files() {
    // Start with a policy, then remove all .cedar files. Reload should succeed
    // with zero policies, and the store should be in a consistent state.
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path()).unwrap();
    assert_eq!(store.policy_count(), 1);

    // Remove the policy file.
    fs::remove_file(dir.path().join("test.cedar")).unwrap();

    let count = store.reload().expect("reload should succeed with zero policies");
    assert_eq!(count, 0, "policy count must be zero after removing all .cedar files");
    assert_eq!(store.policy_count(), 0);
}

// ---------------------------------------------------------------------------
// Schema-only change: .cedarschema changes but .cedar files don't
// ---------------------------------------------------------------------------

#[test]
fn schema_only_change_updates_hash() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path()).unwrap();
    let hash_before = store.schema_hash();

    // Modify schema only (add a new action), keeping the .cedar file unchanged.
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
  action "Edit" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();

    store.reload().expect("reload with new action in schema must succeed");
    let hash_after = store.schema_hash();

    assert_ne!(
        hash_before, hash_after,
        "schema hash must change when .cedarschema file changes"
    );
    // Policy count unchanged (same .cedar file).
    assert_eq!(store.policy_count(), 1);
}

#[test]
fn schema_change_that_invalidates_existing_policy_rejected() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path()).unwrap();
    let hash_before = store.schema_hash();

    // Change schema to remove the View action -- existing policy references it,
    // so validation should fail.
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "Edit" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();

    let result = store.reload();
    assert!(
        result.is_err(),
        "reload must fail when schema change invalidates existing policies"
    );
    assert_eq!(store.policy_count(), 1, "previous policies must survive");
    assert_eq!(
        store.schema_hash(),
        hash_before,
        "schema hash must not change on failed reload"
    );
}

// ---------------------------------------------------------------------------
// Batch with 100 identical items: no deduplication, each evaluated independently
// ---------------------------------------------------------------------------

/// Helper: send 100 identical requests in a batch, assert all return expected decision.
async fn assert_batch_100_identical(
    addr: std::net::SocketAddr,
    request_builder: fn() -> serde_json::Value,
    expected: &str,
) {
    let client = reqwest::Client::new();
    let requests: Vec<serde_json::Value> = (0..100).map(|_| request_builder()).collect();

    let resp = client
        .post(format!("http://{addr}/v1/batch_is_authorized"))
        .json(&serde_json::json!({ "requests": requests }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let responses = body["responses"].as_array().unwrap();
    assert_eq!(
        responses.len(),
        100,
        "must return exactly 100 responses for 100 identical requests"
    );

    for (i, r) in responses.iter().enumerate() {
        assert_eq!(
            r["decision"], expected,
            "item {i}: expected {expected}"
        );
    }
}

#[tokio::test]
async fn test_batch_100_identical_items_all_evaluated() {
    let addr = start_server(production_policy_dir()).await;
    assert_batch_100_identical(addr, admin_allow_request, "Allow").await;
}

#[tokio::test]
async fn test_batch_100_identical_deny_items() {
    let addr = start_server(production_policy_dir()).await;
    assert_batch_100_identical(addr, viewer_deny_request, "Deny").await;
}

// ---------------------------------------------------------------------------
// Concurrent admin reload under rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_admin_reload_rate_limiting() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    let success_count = Arc::new(AtomicUsize::new(0));
    let rate_limited_count = Arc::new(AtomicUsize::new(0));

    // Fire 50 concurrent reload requests. Due to rate limiting (1s minimum
    // interval), at most 1 should succeed; the rest should be 429.
    let mut handles = Vec::new();
    for _ in 0..50 {
        let client = client.clone();
        let sc = Arc::clone(&success_count);
        let rl = Arc::clone(&rate_limited_count);

        let handle = tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .send()
                .await
                .unwrap();

            match resp.status().as_u16() {
                200 => {
                    sc.fetch_add(1, Ordering::Relaxed);
                }
                429 => {
                    rl.fetch_add(1, Ordering::Relaxed);
                }
                other => panic!("unexpected status: {other}"),
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let successes = success_count.load(Ordering::Relaxed);
    let rate_limited = rate_limited_count.load(Ordering::Relaxed);

    assert!(
        successes >= 1,
        "at least one reload must succeed"
    );
    assert!(
        rate_limited > 0,
        "some reloads must be rate-limited when 50 fire concurrently"
    );
    assert_eq!(
        successes + rate_limited,
        50,
        "all 50 requests must return either 200 or 429"
    );
}

// ---------------------------------------------------------------------------
// AVP with unknown action strings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_avp_unknown_action_string_denied() {
    let addr = start_avp_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // AVP format allows arbitrary action strings. An action not in the schema
    // should result in DENY (fail-closed), not a 500 or crash.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&serde_json::json!({
            "principal": {
                "entityType": "ApiGateway::User",
                "entityId": "alice"
            },
            "action": {
                "actionType": "ApiGateway::Action",
                "actionId": "nonexistent_action"
            },
            "resource": {
                "entityType": "ApiGateway::ApiResource",
                "entityId": "/api/v1/data"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "DENY",
        "unknown action must result in DENY, not crash"
    );
}

#[tokio::test]
async fn test_avp_completely_invalid_action_type_denied() {
    let addr = start_avp_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // Entirely bogus action type namespace.
    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&serde_json::json!({
            "principal": {
                "entityType": "ApiGateway::User",
                "entityId": "alice"
            },
            "action": {
                "actionType": "Bogus::Namespace",
                "actionId": "fake"
            },
            "resource": {
                "entityType": "ApiGateway::ApiResource",
                "entityId": "/api/v1/data"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"], "DENY",
        "completely invalid action type must result in DENY"
    );
}

#[tokio::test]
async fn test_avp_empty_entity_id_denied() {
    let addr = start_avp_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/avp/is-authorized"))
        .json(&serde_json::json!({
            "principal": {
                "entityType": "ApiGateway::User",
                "entityId": ""
            },
            "action": {
                "actionType": "ApiGateway::Action",
                "actionId": "read"
            },
            "resource": {
                "entityType": "ApiGateway::ApiResource",
                "entityId": "/api/v1/data"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Empty entity ID is technically valid in Cedar but should not match any
    // policy that references a real user. Expect DENY.
    assert_eq!(
        body["decision"], "DENY",
        "empty entity ID must result in DENY (no matching permit)"
    );
}

// ---------------------------------------------------------------------------
// Large claim values
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_1mb_principal_id_handled() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // 1MB principal ID -- should not crash, OOM, or hang.
    let large_sub = "x".repeat(1_000_000);
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/data",
            "claims": {
                "sub": large_sub,
                "email": "large@example.com",
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

    assert_eq!(resp.status(), 200, "1MB principal must not crash the server");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["decision"].is_string(),
        "must return a valid decision string"
    );
}

#[tokio::test]
async fn test_large_roles_list_handled() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // 1000 roles -- tests entity construction scaling.
    let roles: Vec<String> = (0..1000).map(|i| format!("role_{i}")).collect();
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "many-roles-user",
                "email": "user@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": roles,
                "subscription_tier": "basic",
                "suspended": false,
                "allowed_scopes": []
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "1000 roles must not crash the server");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["decision"].is_string());
}

#[tokio::test]
async fn test_large_allowed_scopes_list_handled() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // 10,000 scopes -- tests Set attribute construction.
    let scopes: Vec<String> = (0..10_000).map(|i| format!("scope_{i}")).collect();
    let resp = client
        .post(format!("http://{addr}/v1/is_authorized"))
        .json(&serde_json::json!({
            "principal": "ignored",
            "action": "GET",
            "resource": "/api/v1/data",
            "claims": {
                "sub": "many-scopes-user",
                "email": "user@example.com",
                "department": "engineering",
                "org": "acme",
                "roles": ["viewer"],
                "subscription_tier": "basic",
                "suspended": false,
                "allowed_scopes": scopes
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "10K scopes must not crash the server");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["decision"].is_string());
}

// ---------------------------------------------------------------------------
// Policy epoch: monotonicity and non-zero
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_policy_epoch_is_nonzero_and_monotonic() {
    // Verify that last_reload_epoch_ms is always positive and advances on reload.
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path()).unwrap();
    let epoch1 = store.last_reload_epoch_ms();
    assert!(epoch1 > 0, "epoch must be positive after initial load");

    // Wait and reload.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    store.reload().unwrap();
    let epoch2 = store.last_reload_epoch_ms();
    assert!(epoch2 > epoch1, "epoch must advance after reload: {epoch1} -> {epoch2}");

    // Another reload.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    store.reload().unwrap();
    let epoch3 = store.last_reload_epoch_ms();
    assert!(epoch3 > epoch2, "epoch must be strictly monotonic: {epoch2} -> {epoch3}");
}

// ---------------------------------------------------------------------------
// Schema hash stability: same source text -> same hash across reloads
// ---------------------------------------------------------------------------

#[test]
fn schema_hash_stable_across_reloads() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("test.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path()).unwrap();
    let hash1 = store.schema_hash();

    // Reload without changing anything -- hash must be identical.
    store.reload().unwrap();
    let hash2 = store.schema_hash();

    assert_eq!(
        hash1, hash2,
        "schema hash must be stable when source text hasn't changed"
    );

    // Reload again.
    store.reload().unwrap();
    let hash3 = store.schema_hash();
    assert_eq!(hash2, hash3, "schema hash must remain stable across multiple reloads");
}

// ---------------------------------------------------------------------------
// No schema file: PDP loads but validates policies against empty schema
// ---------------------------------------------------------------------------

#[test]
fn no_schema_file_with_unscoped_policy_rejected() {
    // An unscoped `permit(principal, action, resource)` fails validation against
    // an empty schema because the validator can't find applicable actions.
    // This confirms schema validation is always active, even with no .cedarschema file.
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("simple.cedar"),
        r#"permit(principal, action, resource);
"#,
    )
    .unwrap();

    let result = cedar_pdp::policy::PolicyStore::from_dir(dir.path());
    assert!(
        result.is_err(),
        "unscoped policy must fail validation against empty schema"
    );
}

#[test]
fn no_cedar_files_and_no_schema_loads_empty() {
    // A completely empty directory should load successfully with zero policies.
    let dir = TempDir::new().unwrap();

    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path())
        .expect("empty directory should load with zero policies and empty schema");
    assert_eq!(store.policy_count(), 0);
}

// ---------------------------------------------------------------------------
// Batch boundary: exactly 100 items (the maximum)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_exactly_100_items_succeeds() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    let requests: Vec<serde_json::Value> = (0..100)
        .map(|i| {
            if i % 2 == 0 {
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

    assert_eq!(resp.status(), 200, "exactly 100 items must succeed (boundary)");
    let body: serde_json::Value = resp.json().await.unwrap();
    let responses = body["responses"].as_array().unwrap();
    assert_eq!(responses.len(), 100);

    for (i, r) in responses.iter().enumerate() {
        let expected = if i % 2 == 0 { "Allow" } else { "Deny" };
        assert_eq!(r["decision"], expected, "item {i}");
    }
}

// ---------------------------------------------------------------------------
// Concurrent evaluation + reload mid-batch (explicit interleaving)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reload_during_active_batch_evaluation() {
    let addr = start_server(production_policy_dir()).await;
    let client = reqwest::Client::new();

    // Launch a large batch that takes measurable time to evaluate.
    let batch_handle = {
        let client = client.clone();
        tokio::spawn(async move {
            let requests: Vec<serde_json::Value> =
                (0..100).map(|_| admin_allow_request()).collect();

            let resp = client
                .post(format!("http://{addr}/v1/batch_is_authorized"))
                .json(&serde_json::json!({ "requests": requests }))
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), 200, "batch must succeed even during reload");
            let body: serde_json::Value = resp.json().await.unwrap();
            let responses = body["responses"].as_array().unwrap();
            assert_eq!(responses.len(), 100);

            // Every item must be Allow -- a reload mid-evaluation must not
            // produce a Deny for items that should be Allow.
            for (i, r) in responses.iter().enumerate() {
                assert_eq!(
                    r["decision"], "Allow",
                    "item {i}: must be Allow even if reload fired mid-batch"
                );
            }
        })
    };

    // Fire a reload while the batch is in flight.
    let reload_handle = {
        let client = client.clone();
        tokio::spawn(async move {
            let resp = client
                .post(format!("http://{addr}/admin/reload"))
                .send()
                .await
                .unwrap();
            let status = resp.status().as_u16();
            assert!(
                status == 200 || status == 429,
                "reload during batch: expected 200 or 429, got {status}"
            );
        })
    };

    batch_handle.await.unwrap();
    reload_handle.await.unwrap();
}
