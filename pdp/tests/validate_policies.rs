use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use std::fs;
use std::path::Path;

/// Validate that all .cedar and .cedarschema files in projects/rust-pdp/policies/
/// parse without errors and that the combined policy set passes Cedar schema validation.
#[test]
fn validate_schema_and_policies() {
    let policies_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pdp crate must have a parent directory")
        .join("policies");

    assert!(
        policies_dir.exists(),
        "policies directory not found at {}",
        policies_dir.display()
    );

    // --- Load schema ---
    let schema_path = policies_dir.join("api_gateway.cedarschema");
    let schema_src = fs::read_to_string(&schema_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", schema_path.display(), e));

    let (schema, schema_warnings) =
        Schema::from_cedarschema_str(&schema_src).expect("Schema should parse without errors");

    // Warn on schema issues but do not fail -- warnings are non-fatal.
    for w in schema_warnings {
        eprintln!("Schema warning: {w}");
    }

    // --- Load all .cedar policy files ---
    let mut combined_src = String::new();
    let mut file_count = 0;

    let mut entries: Vec<_> = fs::read_dir(&policies_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in &entries {
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "cedar") {
            let src = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
            combined_src.push_str(&src);
            combined_src.push('\n');
            file_count += 1;
        }
    }

    assert!(
        file_count >= 5,
        "Expected at least 5 .cedar policy files, found {file_count}"
    );

    // --- Parse combined policy set ---
    let policy_set: PolicySet = combined_src
        .parse()
        .expect("All .cedar files should parse as a valid PolicySet");

    let total = policy_set.policies().count() + policy_set.templates().count();
    assert!(
        total >= 5,
        "Expected at least 5 policies/templates, found {total}"
    );

    // --- Validate policy set against schema ---
    let validator = Validator::new(schema);
    let result = validator.validate(&policy_set, ValidationMode::default());

    if !result.validation_passed() {
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        panic!(
            "Policy validation failed against schema:\n{}",
            errors.join("\n")
        );
    }
}
