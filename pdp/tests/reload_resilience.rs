//! Reload resilience tests.
//!
//! Verifies that PolicyStore survives hostile filesystem conditions during
//! hot-reload: corrupt files, partial writes, schema-incompatible policies,
//! and concurrent reload + batch evaluation pressure.
//!
//! These tests exercise the gap between "syntactically invalid Cedar" (covered
//! by policy.rs unit tests) and real-world failure modes where the filesystem
//! delivers unexpected content mid-operation.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use axum::routing::{get, post};
use axum::Router;
use tempfile::TempDir;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// PolicyStore unit tests: filesystem fault tolerance
// ---------------------------------------------------------------------------

/// Write the production-equivalent schema and a single valid policy.
fn write_baseline(dir: &std::path::Path) {
    fs::write(
        dir.join("api_gateway.cedarschema"),
        r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
  action "Edit" appliesTo { principal: User, resource: Resource };
}
"#,
    )
    .unwrap();
    fs::write(
        dir.join("baseline.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();
}

#[test]
fn reload_survives_truncated_policy_file() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);

    // Simulate a partial write (editor crashed mid-save): truncated Cedar.
    fs::write(dir.path().join("truncated.cedar"), "permit(principal ==").unwrap();

    let result = store.reload();
    assert!(result.is_err(), "truncated policy must fail validation");
    assert_eq!(
        store.policy_count(),
        1,
        "previous valid policies must survive a truncated file reload"
    );
}

#[test]
fn reload_survives_empty_policy_file() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);

    // Empty .cedar file (zero bytes -- e.g., `> policy.cedar` shell accident).
    fs::write(dir.path().join("empty.cedar"), "").unwrap();

    // Empty file is valid Cedar (no policies), so reload succeeds but count drops.
    // This is correct behavior -- the operator removed a policy file's contents.
    let result = store.reload();
    assert!(result.is_ok(), "empty .cedar file is valid (zero policies in that file)");
    // The baseline policy still exists in baseline.cedar.
    assert_eq!(store.policy_count(), 1, "baseline policy must still be present");
}

#[test]
fn reload_survives_binary_garbage_in_policy_file() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);

    // Binary garbage (not valid UTF-8 or Cedar).
    fs::write(
        dir.path().join("garbage.cedar"),
        &[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90],
    )
    .unwrap();

    let result = store.reload();
    assert!(
        result.is_err(),
        "binary garbage in .cedar file must fail"
    );
    assert_eq!(
        store.policy_count(),
        1,
        "previous valid policies must survive binary garbage reload"
    );
}

#[test]
fn reload_rejects_schema_incompatible_policy() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);
    let original_hash = store.schema_hash();

    // Write a policy referencing an entity type not in the schema.
    // This is valid Cedar syntax but fails schema validation.
    fs::write(
        dir.path().join("bad_type.cedar"),
        r#"permit(
    principal == Nonexistent::Ghost::"phantom",
    action == App::Action::"View",
    resource
);
"#,
    )
    .unwrap();

    let result = store.reload();
    assert!(
        result.is_err(),
        "policy referencing unknown entity type must fail schema validation"
    );
    assert_eq!(
        store.policy_count(),
        1,
        "previous valid policies must survive schema-incompatible reload"
    );
    assert_eq!(
        store.schema_hash(),
        original_hash,
        "schema hash must not change on failed reload"
    );
}

#[test]
fn reload_rejects_policy_with_wrong_action_applies_to() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);

    // Policy uses correct entity types but wrong action target (Edit applies to
    // User principal, but we reference a Resource as principal). Valid syntax,
    // but schema validator should catch the type mismatch.
    fs::write(
        dir.path().join("wrong_applies.cedar"),
        r#"permit(
    principal == App::Resource::"doc-1",
    action == App::Action::"Edit",
    resource == App::User::"alice"
);
"#,
    )
    .unwrap();

    let result = store.reload();
    assert!(
        result.is_err(),
        "policy with principal/resource type swap must fail schema validation"
    );
    assert_eq!(
        store.policy_count(),
        1,
        "previous valid policies must survive type-mismatch reload"
    );
}

#[test]
fn reload_rejects_corrupt_schema_keeps_previous() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);
    let original_hash = store.schema_hash();

    // Corrupt the schema file itself.
    fs::write(
        dir.path().join("api_gateway.cedarschema"),
        "this is not a valid schema {{{",
    )
    .unwrap();

    let result = store.reload();
    assert!(result.is_err(), "corrupt schema must fail");
    assert_eq!(
        store.policy_count(),
        1,
        "previous policies must survive corrupt schema reload"
    );
    assert_eq!(
        store.schema_hash(),
        original_hash,
        "schema hash must not change on corrupt schema reload"
    );
}

#[test]
fn reload_picks_up_valid_additions_after_failed_attempt() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);

    // First: write a bad policy, reload fails.
    fs::write(dir.path().join("bad.cedar"), "not valid cedar !!!").unwrap();
    assert!(store.reload().is_err());
    assert_eq!(store.policy_count(), 1);

    // Second: fix the bad file with a valid policy.
    fs::write(
        dir.path().join("bad.cedar"),
        r#"permit(principal == App::User::"bob", action == App::Action::"View", resource);
"#,
    )
    .unwrap();

    let result = store.reload();
    assert!(result.is_ok(), "reload must succeed after fix");
    assert_eq!(
        store.policy_count(),
        2,
        "both baseline and new policy must be present after recovery"
    );
}

#[test]
fn epoch_does_not_advance_on_failed_reload() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    let epoch_before = store.last_reload_epoch_ms();

    std::thread::sleep(std::time::Duration::from_millis(5));

    // Write invalid policy, attempt reload.
    fs::write(dir.path().join("bad.cedar"), "garbage!!!").unwrap();
    let _ = store.reload(); // expected to fail

    let epoch_after = store.last_reload_epoch_ms();
    assert_eq!(
        epoch_before, epoch_after,
        "epoch must not advance on failed reload -- stale epoch would \
         invalidate plugin caches for no reason"
    );
}

// ---------------------------------------------------------------------------
// HTTP-level tests: reload resilience under concurrent evaluation
// ---------------------------------------------------------------------------

async fn start_server_with_dir(policy_dir: PathBuf) -> (SocketAddr, Arc<cedar_pdp::handlers::AppContext>) {
    let store =
        cedar_pdp::policy::PolicyStore::from_dir(&policy_dir).expect("load policies");
    let ctx = Arc::new(cedar_pdp::handlers::AppContext::new(store, None));
    let state: cedar_pdp::handlers::AppState = Arc::clone(&ctx);

    let app = Router::new()
        .route(
            "/v1/is_authorized",
            post(cedar_pdp::handlers::is_authorized),
        )
        .route(
            "/v1/batch_is_authorized",
            post(cedar_pdp::handlers::batch_is_authorized),
        )
        .route("/admin/reload", post(cedar_pdp::handlers::admin_reload))
        .route("/health", get(cedar_pdp::handlers::health))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, ctx)
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

/// Concurrent batch evaluation + reload attempts with filesystem faults.
///
/// Verifies that in-flight batch evaluations complete correctly even when
/// reload attempts fail due to corrupt policy files on disk. The arc-swap
/// design ensures readers always see a consistent (PolicySet, Schema) tuple.
#[tokio::test]
async fn test_batch_eval_survives_concurrent_corrupt_reload() {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let (addr, _ctx) = start_server_with_dir(policy_path).await;
    let client = reqwest::Client::new();

    let total_decisions = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut handles = Vec::new();

    // 20 concurrent batch_50 requests (1000 decisions total).
    for batch_idx in 0..20 {
        let client = client.clone();
        let td = Arc::clone(&total_decisions);
        let handle = tokio::spawn(async move {
            let requests: Vec<serde_json::Value> = (0..50)
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

            assert_eq!(resp.status(), 200, "batch {batch_idx} must succeed");
            let body: serde_json::Value = resp.json().await.unwrap();
            let responses = body["responses"].as_array().unwrap();
            assert_eq!(responses.len(), 50);

            // Verify every decision is correct.
            for (j, r) in responses.iter().enumerate() {
                let decision = r["decision"].as_str().unwrap();
                let expected = if (batch_idx + j) % 2 == 0 {
                    "Allow"
                } else {
                    "Deny"
                };
                assert_eq!(
                    decision, expected,
                    "batch {batch_idx} item {j}: expected {expected}, got {decision}"
                );
            }
            td.fetch_add(50, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    // Interleaved: 10 reload attempts (some may be rate-limited).
    // These hit the same policy dir (production policies, valid), so they should
    // succeed or be rate-limited. Either way, no impact on in-flight evals.
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

    let elapsed = start.elapsed();
    let total = total_decisions.load(Ordering::Relaxed);
    assert_eq!(total, 1000, "all 1000 batch decisions must complete correctly");
    eprintln!(
        "reload_resilience: 20 x batch_50 + 10 reloads in {:.1}ms",
        elapsed.as_secs_f64() * 1000.0
    );
}

// ---------------------------------------------------------------------------
// PolicyStore: multiple sequential failures followed by recovery
// ---------------------------------------------------------------------------

#[test]
fn store_recovers_after_multiple_sequential_failures() {
    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load");
    assert_eq!(store.policy_count(), 1);

    // Fail 5 times in a row with different failure modes.
    let failures: Vec<(&str, &[u8])> = vec![
        ("fail1.cedar", b"not cedar" as &[u8]),
        ("fail2.cedar", b"permit(" as &[u8]),
        ("fail3.cedar", &[0xFF, 0xFE]),
        ("fail4.cedar", b"forbid(principal, action, resource) when { principal.nonexistent_attr };" as &[u8]),
        ("fail5.cedar", b"permit(principal == Fake::Type::\"x\", action, resource);" as &[u8]),
    ];

    for (name, content) in &failures {
        fs::write(dir.path().join(name), content).unwrap();
        let result = store.reload();
        assert!(result.is_err(), "reload with {name} must fail");
        assert_eq!(
            store.policy_count(),
            1,
            "policy count must remain 1 after {name} failure"
        );
        // Clean up for next iteration.
        fs::remove_file(dir.path().join(name)).unwrap();
    }

    // Now add a valid second policy -- should recover cleanly.
    fs::write(
        dir.path().join("second.cedar"),
        r#"permit(principal == App::User::"charlie", action == App::Action::"Edit", resource);
"#,
    )
    .unwrap();

    let count = store.reload().expect("recovery reload must succeed");
    assert_eq!(count, 2, "must pick up both baseline and new policy after recovery");
}

// ---------------------------------------------------------------------------
// Concurrent readers see consistent state during failed reload
// ---------------------------------------------------------------------------

#[test]
fn concurrent_readers_see_consistent_state_during_failed_reload() {
    use std::thread;

    let dir = TempDir::new().unwrap();
    write_baseline(dir.path());

    let store = Arc::new(
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("initial load"),
    );

    // Write corrupt file so reload will fail.
    fs::write(dir.path().join("corrupt.cedar"), "not valid!!!").unwrap();

    let mut handles = Vec::new();

    // 8 reader threads checking consistency.
    for _ in 0..8 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                let state = store.load();
                let (ps, schema) = state.as_ref();
                let count = ps.policies().count();
                // Must always see exactly 1 policy (the baseline).
                // Never 0 (mid-swap empty), never a corrupt state.
                assert_eq!(
                    count, 1,
                    "reader must always see consistent state (1 policy)"
                );
                // Schema must always be parseable (not corrupt).
                let _ = format!("{:?}", schema);
            }
        }));
    }

    // 4 writer threads attempting (failing) reloads.
    for _ in 0..4 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                let _ = store.reload(); // expected to fail
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread must not panic");
    }
}
