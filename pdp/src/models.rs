use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::entities::Claims;

#[derive(Debug, Deserialize)]
pub struct AuthzRequest {
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub claims: Option<Claims>,
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

#[derive(Debug, Deserialize)]
pub struct BatchAuthzRequest {
    pub requests: Vec<AuthzRequest>,
}

#[derive(Debug, Serialize)]
pub struct BatchAuthzResponse {
    pub responses: Vec<AuthzResponse>,
}

#[derive(Debug, Serialize)]
pub struct PolicyInfoResponse {
    pub policy_count: usize,
    pub last_reload_epoch_ms: u64,
    pub schema_hash: String,
}
