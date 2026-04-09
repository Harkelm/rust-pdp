//! Policy evolution tests -- schema migration under hot-reload.
//!
//! Validates what happens when:
//!   1. Schema adds new entity types or attributes (forward evolution)
//!   2. Schema removes attributes (backward incompatible)
//!   3. New policies are added that reference new schema elements
//!   4. Rolling deployment where PDP instances may temporarily have different schemas
//!
//! These scenarios are critical for production: policy changes are the most
//! common operational action, and schema evolution is inevitable as the
//! authorization model grows.

use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Schema / policy content for evolution scenarios
// ---------------------------------------------------------------------------

/// V1 schema: minimal User + Resource + read/write actions.
const SCHEMA_V1: &str = r#"namespace App {
  entity User {
    email: String,
    org: String,
  };
  entity Resource {
    owner_org: String,
  };
  action "read" appliesTo { principal: User, resource: Resource };
  action "write" appliesTo { principal: User, resource: Resource };
}
"#;

/// V2 schema: adds department attribute to User and a new Team entity type.
const SCHEMA_V2: &str = r#"namespace App {
  entity User {
    email: String,
    org: String,
    department: String,
  };
  entity Team {
    org: String,
  };
  entity Resource {
    owner_org: String,
    classification: String,
  };
  action "read" appliesTo { principal: User, resource: Resource };
  action "write" appliesTo { principal: User, resource: Resource };
  action "admin" appliesTo { principal: User, resource: Resource };
}
"#;

/// V1 policy: simple org-scoped access.
const POLICY_V1: &str = r#"
permit(
    principal,
    action == App::Action::"read",
    resource
) when { principal.org == resource.owner_org };
"#;

/// V2 policy: uses new department attribute from V2 schema.
const POLICY_V2_DEPT: &str = r#"
permit(
    principal,
    action == App::Action::"write",
    resource
) when {
    principal.org == resource.owner_org &&
    principal.department == "engineering"
};
"#;

/// V2 policy: uses new admin action from V2 schema.
const POLICY_V2_ADMIN: &str = r#"
permit(
    principal,
    action == App::Action::"admin",
    resource
) when { principal.department == "engineering" };
"#;

/// Write schema + policies, return (TempDir, PolicyStore).
fn setup_v1() -> (TempDir, cedar_pdp::policy::PolicyStore) {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.cedarschema"), SCHEMA_V1).unwrap();
    fs::write(dir.path().join("access.cedar"), POLICY_V1).unwrap();
    let store = cedar_pdp::policy::PolicyStore::from_dir(dir.path())
        .expect("V1 schema + policies must load");
    (dir, store)
}

// ---------------------------------------------------------------------------
// Test: forward schema evolution (add attributes + entity types)
// ---------------------------------------------------------------------------

#[test]
fn schema_evolution_v1_to_v2_adds_attributes() {
    let (dir, store) = setup_v1();
    let original_hash = store.schema_hash();
    let original_count = store.policy_count();
    assert_eq!(original_count, 1, "V1 should have 1 policy");

    // Evolve: replace schema with V2, add V2 policy that uses new attribute.
    fs::write(dir.path().join("app.cedarschema"), SCHEMA_V2).unwrap();
    fs::write(dir.path().join("dept_access.cedar"), POLICY_V2_DEPT).unwrap();

    let new_count = store.reload().expect("V2 reload must succeed");
    assert_eq!(new_count, 2, "V2 should have 2 policies (original + dept)");
    assert_ne!(
        store.schema_hash(),
        original_hash,
        "schema hash must change after schema evolution"
    );
}

#[test]
fn schema_evolution_v2_adds_new_action() {
    let (dir, store) = setup_v1();

    // Evolve to V2 with new admin action + policy.
    fs::write(dir.path().join("app.cedarschema"), SCHEMA_V2).unwrap();
    fs::write(dir.path().join("admin_access.cedar"), POLICY_V2_ADMIN).unwrap();

    let new_count = store.reload().expect("V2 reload with new action must succeed");
    assert_eq!(new_count, 2, "V2 should have 2 policies");
}

// ---------------------------------------------------------------------------
// Test: backward-incompatible schema change (remove attribute)
// ---------------------------------------------------------------------------

/// V3 schema: removes `org` from User (backward-incompatible if V1 policy references it).
const SCHEMA_V3_BREAKING: &str = r#"namespace App {
  entity User {
    email: String,
  };
  entity Resource {
    owner_org: String,
  };
  action "read" appliesTo { principal: User, resource: Resource };
  action "write" appliesTo { principal: User, resource: Resource };
}
"#;

#[test]
fn schema_evolution_rejects_breaking_change() {
    let (dir, store) = setup_v1();
    let original_hash = store.schema_hash();

    // Replace schema with V3 that removes `org`. The existing V1 policy
    // references `principal.org`, which should fail validation.
    fs::write(dir.path().join("app.cedarschema"), SCHEMA_V3_BREAKING).unwrap();

    let result = store.reload();
    assert!(
        result.is_err(),
        "backward-incompatible schema change must fail when existing policies reference removed attributes"
    );
    assert_eq!(
        store.policy_count(),
        1,
        "previous policies must survive breaking schema change"
    );
    assert_eq!(
        store.schema_hash(),
        original_hash,
        "schema hash must not change on failed evolution"
    );
}

// ---------------------------------------------------------------------------
// Test: schema + policy updated atomically
// ---------------------------------------------------------------------------

#[test]
fn schema_and_policy_evolve_atomically() {
    let (dir, store) = setup_v1();
    let epoch_before = store.last_reload_epoch_ms();

    // Wait a bit so epoch changes are measurable.
    std::thread::sleep(std::time::Duration::from_millis(5));

    // Update schema and policy file in the same reload cycle.
    fs::write(dir.path().join("app.cedarschema"), SCHEMA_V2).unwrap();
    // Replace V1 policy with V2 policy that uses new attributes.
    fs::write(dir.path().join("access.cedar"), POLICY_V2_DEPT).unwrap();
    fs::write(dir.path().join("admin_access.cedar"), POLICY_V2_ADMIN).unwrap();

    let new_count = store.reload().expect("atomic schema+policy evolution must succeed");
    assert_eq!(new_count, 2, "should have 2 V2 policies");

    let epoch_after = store.last_reload_epoch_ms();
    assert!(
        epoch_after > epoch_before,
        "epoch must advance on successful evolution"
    );
}

// ---------------------------------------------------------------------------
// Test: partial schema evolution (new policy without schema update) fails
// ---------------------------------------------------------------------------

#[test]
fn new_policy_without_schema_update_fails_validation() {
    let (dir, store) = setup_v1();

    // Add V2 policy that references `principal.department` without updating schema.
    // V1 schema doesn't have `department` on User, so validation must fail.
    fs::write(dir.path().join("dept_access.cedar"), POLICY_V2_DEPT).unwrap();

    let result = store.reload();
    assert!(
        result.is_err(),
        "policy referencing attributes not in current schema must fail validation"
    );
    assert_eq!(
        store.policy_count(),
        1,
        "previous policies must survive partial evolution failure"
    );
}

// ---------------------------------------------------------------------------
// Test: concurrent reads during schema evolution see consistent state
// ---------------------------------------------------------------------------

#[test]
fn concurrent_reads_during_schema_evolution() {
    let (dir, raw_store) = setup_v1();
    let store = Arc::new(raw_store);

    let mut handles = Vec::new();

    // 4 reader threads continuously loading state.
    for _ in 0..4 {
        let store = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for _ in 0..500 {
                let state = store.load();
                let (ps, _schema) = state.as_ref();
                let count = ps.policies().count();
                // Must always see either 1 (V1) or 2 (V2) policies, never 0 or partial.
                assert!(
                    count == 1 || count == 2,
                    "reader must see consistent state: got {count} policies"
                );
            }
        }));
    }

    // 1 writer thread performing the evolution.
    {
        let dir_path = dir.path().to_path_buf();
        let store = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            // Small delay to let readers start.
            std::thread::sleep(std::time::Duration::from_millis(1));
            fs::write(dir_path.join("app.cedarschema"), SCHEMA_V2).unwrap();
            fs::write(dir_path.join("dept_access.cedar"), POLICY_V2_DEPT).unwrap();
            let _ = store.reload(); // may succeed or fail depending on timing
        }));
    }

    for handle in handles {
        handle.join().expect("thread must not panic");
    }
}
