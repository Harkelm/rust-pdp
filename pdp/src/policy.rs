use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use cedar_policy::{Entities, PolicySet, Schema};
use sha2::{Digest, Sha256};

/// Shared policy state: single tuple swap per ADR-004.
pub type PolicyState = Arc<(PolicySet, Schema)>;

pub struct PolicyStore {
    state: ArcSwap<(PolicySet, Schema)>,
    policy_dir: PathBuf,
    last_reload_epoch_ms: AtomicU64,
    schema_hash: ArcSwap<String>,
}

impl PolicyStore {
    /// Load all .cedar files and .cedarschema files from a directory.
    pub fn from_dir(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let (policy_set, schema) = Self::load_from_dir(dir)?;
        let schema_hash = Self::compute_schema_hash(&schema);
        let now = now_epoch_ms();

        Ok(Self {
            state: ArcSwap::from_pointee((policy_set, schema)),
            policy_dir: dir.to_path_buf(),
            last_reload_epoch_ms: AtomicU64::new(now),
            schema_hash: ArcSwap::from_pointee(schema_hash),
        })
    }

    /// Lock-free read of current policy state.
    pub fn load(&self) -> arc_swap::Guard<Arc<(PolicySet, Schema)>> {
        self.state.load()
    }

    /// Attempt to reload policies from disk. Returns Ok(policy_count) on success.
    /// On validation failure, the existing policies remain active.
    pub fn reload(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let (policy_set, schema) = Self::load_from_dir(&self.policy_dir)?;
        let count = policy_set.policies().count();
        let hash = Self::compute_schema_hash(&schema);

        self.state.store(Arc::new((policy_set, schema)));
        self.schema_hash.store(Arc::new(hash));
        self.last_reload_epoch_ms
            .store(now_epoch_ms(), Ordering::Relaxed);

        Ok(count)
    }

    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }

    pub fn last_reload_epoch_ms(&self) -> u64 {
        self.last_reload_epoch_ms.load(Ordering::Relaxed)
    }

    pub fn schema_hash(&self) -> String {
        (**self.schema_hash.load()).clone()
    }

    fn compute_schema_hash(schema: &Schema) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", schema));
        format!("{:x}", hasher.finalize())
    }

    fn load_from_dir(dir: &Path) -> Result<(PolicySet, Schema), Box<dyn std::error::Error>> {
        let mut policy_src = String::new();
        let mut schema_src = String::new();

        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("cedar") => {
                    policy_src.push_str(&std::fs::read_to_string(&path)?);
                    policy_src.push('\n');
                }
                Some("cedarschema") => {
                    schema_src.push_str(&std::fs::read_to_string(&path)?);
                    schema_src.push('\n');
                }
                _ => {}
            }
        }

        let schema = if schema_src.is_empty() {
            Schema::from_cedarschema_str("").map(|(s, _)| s)?
        } else {
            Schema::from_cedarschema_str(&schema_src).map(|(s, _)| s)?
        };

        let policy_set: PolicySet = policy_src.parse()?;

        // Validate policies against schema (Validator::new takes ownership, clone for validation)
        let validation = cedar_policy::Validator::new(schema.clone());
        let result = validation.validate(&policy_set, cedar_policy::ValidationMode::default());
        if !result.validation_passed() {
            let errors: Vec<String> = result
                .validation_errors()
                .map(|e| e.to_string())
                .collect();
            return Err(format!("Policy validation failed: {}", errors.join("; ")).into());
        }

        Ok((policy_set, schema))
    }

    /// Validate entities against schema before evaluation (P0-2).
    /// Returns an error if entity validation fails -- deny, not pass-through.
    pub fn validate_entities(
        &self,
        entities_json: &[serde_json::Value],
    ) -> Result<Entities, Box<dyn std::error::Error>> {
        let state = self.load();
        let (_, schema) = state.as_ref();

        let entities_array = serde_json::Value::Array(entities_json.to_vec());
        let entities = Entities::from_json_value(entities_array, Some(schema))?;
        Ok(entities)
    }

    pub fn policy_count(&self) -> usize {
        let state = self.load();
        let (ps, _) = state.as_ref();
        ps.policies().count()
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_valid_policy(dir: &Path) {
        fs::write(
            dir.join("test.cedarschema"),
            r#"namespace App {
  entity User;
  entity Resource;
  action "View" appliesTo { principal: User, resource: Resource };
}
"#,
        )
        .unwrap();
        fs::write(
            dir.join("test.cedar"),
            r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
"#,
        )
        .unwrap();
    }

    fn write_updated_policy(dir: &Path) {
        fs::write(
            dir.join("test.cedar"),
            r#"permit(principal == App::User::"alice", action == App::Action::"View", resource);
permit(principal == App::User::"bob", action == App::Action::"View", resource);
"#,
        )
        .unwrap();
    }

    #[test]
    fn reload_picks_up_new_policies() {
        let dir = TempDir::new().unwrap();
        write_valid_policy(dir.path());

        let store = PolicyStore::from_dir(dir.path()).expect("initial load");
        let initial_count = store.policy_count();
        assert_eq!(initial_count, 1);

        write_updated_policy(dir.path());

        let new_count = store.reload().expect("reload should succeed");
        assert_eq!(new_count, 2);
        assert_eq!(store.policy_count(), 2);
    }

    #[test]
    fn reload_rejects_invalid_cedar_keeps_previous() {
        let dir = TempDir::new().unwrap();
        write_valid_policy(dir.path());

        let store = PolicyStore::from_dir(dir.path()).expect("initial load");
        assert_eq!(store.policy_count(), 1);

        // Write syntactically broken Cedar
        fs::write(dir.path().join("bad.cedar"), "this is not valid cedar !!!").unwrap();

        let result = store.reload();
        assert!(result.is_err(), "reload of invalid policy must fail");
        // Previous policies must still be active
        assert_eq!(store.policy_count(), 1);
    }

    #[test]
    fn last_reload_timestamp_updates_on_success() {
        let dir = TempDir::new().unwrap();
        write_valid_policy(dir.path());

        let store = PolicyStore::from_dir(dir.path()).expect("initial load");
        let t0 = store.last_reload_epoch_ms();

        std::thread::sleep(std::time::Duration::from_millis(5));
        write_updated_policy(dir.path());
        store.reload().unwrap();

        let t1 = store.last_reload_epoch_ms();
        assert!(t1 > t0, "timestamp must advance after successful reload");
    }

    #[test]
    fn schema_hash_changes_on_schema_update() {
        let dir = TempDir::new().unwrap();
        write_valid_policy(dir.path());

        let store = PolicyStore::from_dir(dir.path()).expect("initial load");
        let h0 = store.schema_hash();

        // Write a new schema with an extra action
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
        // Update policy so validation still passes (no policy references Edit yet)
        store.reload().unwrap();

        let h1 = store.schema_hash();
        assert_ne!(h0, h1, "hash must change when schema changes");
    }
}
