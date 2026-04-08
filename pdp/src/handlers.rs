use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request};

use crate::models::{AuthzRequest, AuthzResponse, Diagnostics, ErrorResponse, HealthResponse};
use crate::policy::PolicyStore;

pub type AppState = Arc<PolicyStore>;

pub async fn health(State(store): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        policies_loaded: store.policy_count(),
    })
}

pub async fn is_authorized(
    State(store): State<AppState>,
    Json(req): Json<AuthzRequest>,
) -> Result<Json<AuthzResponse>, (StatusCode, Json<ErrorResponse>)> {
    let principal = parse_entity_uid(&req.principal).map_err(|e| bad_request(&e))?;
    let action = parse_entity_uid(&req.action).map_err(|e| bad_request(&e))?;
    let resource = parse_entity_uid(&req.resource).map_err(|e| bad_request(&e))?;

    let context = Context::from_json_value(
        serde_json::to_value(&req.context).unwrap_or(serde_json::Value::Object(Default::default())),
        None,
    )
    .map_err(|e| bad_request(&format!("invalid context: {e}")))?;

    let cedar_request = Request::new(
        principal,
        action,
        resource,
        context,
        None, // schema validation on request is optional; we validate entities separately
    )
    .map_err(|e| bad_request(&format!("invalid request: {e}")))?;

    // Load policy state (lock-free via arc-swap)
    let state = store.load();
    let (policy_set, _schema) = state.as_ref();

    // P0-2: Schema validation of entities happens at entity construction time.
    // For MVP with no PEP-supplied entities, we use an empty entity set.
    let entities = Entities::empty();

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&cedar_request, policy_set, &entities);

    let decision = match response.decision() {
        Decision::Allow => "Allow",
        Decision::Deny => "Deny",
    };

    let reason: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|id| id.to_string())
        .collect();

    let errors: Vec<String> = response
        .diagnostics()
        .errors()
        .map(|e| e.to_string())
        .collect();

    Ok(Json(AuthzResponse {
        decision: decision.to_string(),
        diagnostics: Diagnostics { reason, errors },
    }))
}

/// Parse Cedar entity UID from string like `Type::"id"`.
fn parse_entity_uid(s: &str) -> Result<EntityUid, String> {
    s.parse::<EntityUid>()
        .map_err(|e| format!("invalid entity UID: {s} ({e})"))
}

fn bad_request(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}
