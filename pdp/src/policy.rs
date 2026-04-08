use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use cedar_policy::{Entities, PolicySet, Schema};

/// Shared policy state: single tuple swap per ADR-004.
pub type PolicyState = Arc<(PolicySet, Schema)>;

pub struct PolicyStore {
    state: ArcSwap<(PolicySet, Schema)>,
}

impl PolicyStore {
    /// Load all .cedar files and .cedarschema files from a directory.
    pub fn from_dir(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let (policy_set, schema) = Self::load_from_dir(dir)?;
        Ok(Self {
            state: ArcSwap::from_pointee((policy_set, schema)),
        })
    }

    /// Lock-free read of current policy state.
    pub fn load(&self) -> arc_swap::Guard<Arc<(PolicySet, Schema)>> {
        self.state.load()
    }

    fn load_from_dir(dir: &Path) -> Result<(PolicySet, Schema), Box<dyn std::error::Error>> {
        let mut policy_src = String::new();
        let mut schema_src = String::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
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
