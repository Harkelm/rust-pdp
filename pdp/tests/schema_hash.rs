//! Schema hash stability and correctness tests.
//!
//! Verifies that the SHA256 hash computed from raw schema source text behaves
//! deterministically and is sensitive to whitespace changes. The hash is used
//! for cache invalidation in the Kong plugin -- incorrect behavior here causes
//! either stale caches (hash unchanged when schema changed) or unnecessary
//! cache churn (hash changing when schema is semantically identical).

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

/// Write a minimal valid schema and policy to a temp dir and return the store.
fn store_with_schema(schema_src: &str) -> (TempDir, cedar_pdp::policy::PolicyStore) {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.cedarschema"), schema_src).unwrap();
    fs::write(
        dir.path().join("test.cedar"),
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
    )
    .unwrap();
    let store =
        cedar_pdp::policy::PolicyStore::from_dir(dir.path()).expect("load schema + policy");
    (dir, store)
}

const BASE_SCHEMA: &str = r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#;

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

/// Loading the same schema source text twice must produce identical hashes.
#[test]
fn test_schema_hash_deterministic() {
    let (_dir1, store1) = store_with_schema(BASE_SCHEMA);
    let (_dir2, store2) = store_with_schema(BASE_SCHEMA);

    let h1 = store1.schema_hash();
    let h2 = store2.schema_hash();

    assert_eq!(
        h1, h2,
        "identical schema source text must produce identical hashes"
    );
}

/// Reloading the same schema (no changes on disk) must produce the same hash.
#[test]
fn test_schema_hash_stable_across_reload() {
    let (_dir, store) = store_with_schema(BASE_SCHEMA);
    let h_before = store.schema_hash();

    store.reload().expect("reload same schema must succeed");
    let h_after = store.schema_hash();

    assert_eq!(
        h_before, h_after,
        "hash must not change when schema source is unchanged"
    );
}

// ---------------------------------------------------------------------------
// Whitespace sensitivity
// ---------------------------------------------------------------------------

/// The hash is computed from raw source text, not parsed form. Adding
/// whitespace changes the text and therefore the hash. This is intentional:
/// schema files should not be reformatted without understanding the cache
/// invalidation implications.
#[test]
fn test_schema_hash_whitespace_sensitive() {
    let schema_with_extra_whitespace = r#"namespace App {
  entity   User;
  entity   Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#;

    let (_dir1, store1) = store_with_schema(BASE_SCHEMA);
    let (_dir2, store2) = store_with_schema(schema_with_extra_whitespace);

    let h1 = store1.schema_hash();
    let h2 = store2.schema_hash();

    assert_ne!(
        h1, h2,
        "whitespace changes in schema source must change the hash \
         (hash is text-based, not AST-based)"
    );
}

// ---------------------------------------------------------------------------
// Format validation
// ---------------------------------------------------------------------------

/// The schema hash must be a valid SHA256 hex string: exactly 64 characters,
/// all lowercase hexadecimal.
#[test]
fn test_schema_hash_is_64_char_hex() {
    let (_dir, store) = store_with_schema(BASE_SCHEMA);
    let hash = store.schema_hash();

    assert_eq!(
        hash.len(),
        64,
        "SHA256 hex must be exactly 64 characters, got {}",
        hash.len()
    );
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "hash must contain only hex characters, got: {hash}"
    );
    assert!(
        hash.chars().all(|c| !c.is_ascii_uppercase()),
        "hash must be lowercase hex, got: {hash}"
    );
}

/// Schema hash from production policies must also be valid 64-char hex.
#[test]
fn test_production_schema_hash_format() {
    let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    let store =
        cedar_pdp::policy::PolicyStore::from_dir(&policy_dir).expect("load production policies");
    let hash = store.schema_hash();

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}
