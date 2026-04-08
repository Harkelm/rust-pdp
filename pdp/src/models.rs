use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct AuthzRequest {
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AuthzResponse {
    pub decision: String,
    pub diagnostics: Diagnostics,
}

#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub reason: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub policies_loaded: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct PolicyInfoResponse {
    pub policy_count: usize,
    pub last_reload_epoch_ms: u64,
    pub schema_hash: String,
}
