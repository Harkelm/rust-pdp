use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request};

use crate::entities::{build_entities, build_request_uids, RequestContext};
use crate::models::{
    AuthzRequest, AuthzResponse, Diagnostics, ErrorResponse, HealthResponse, PolicyInfoResponse,
};
use crate::policy::PolicyStore;

pub type AppState = Arc<PolicyStore>;

pub async fn health(State(store): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        policies_loaded: store.policy_count(),
    })
}

pub async fn policy_info(State(store): State<AppState>) -> Json<PolicyInfoResponse> {
    Json(PolicyInfoResponse {
        policy_count: store.policy_count(),
        last_reload_epoch_ms: store.last_reload_epoch_ms(),
        schema_hash: store.schema_hash(),
    })
}

pub async fn admin_reload(
    State(store): State<AppState>,
) -> Result<Json<PolicyInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let old_count = store.policy_count();
    match store.reload() {
        Ok(new_count) => {
            tracing::info!(old_count, new_count, "manual policy reload successful");
            Ok(Json(PolicyInfoResponse {
                policy_count: new_count,
                last_reload_epoch_ms: store.last_reload_epoch_ms(),
                schema_hash: store.schema_hash(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("reload failed: {e}"),
            }),
        )),
    }
}

pub async fn is_authorized(
    State(store): State<AppState>,
    Json(req): Json<AuthzRequest>,
) -> Result<Json<AuthzResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Load policy state (lock-free via arc-swap) before branching so we can
    // pass the schema to entity construction for P0-2 validation.
    let state = store.load();
    let (policy_set, schema) = state.as_ref();

    let (principal, action, resource, entities) = if let Some(claims) = &req.claims {
        // Claims path: treat req.action as HTTP method and req.resource as path.
        // Entity UIDs are derived from claims and request context; the schema is
        // used for entity validation (P0-2).
        let request_ctx = RequestContext {
            method: req.action.clone(),
            path: req.resource.clone(),
            service: None,
        };
        let (principal, action, resource) = build_request_uids(claims, &request_ctx)
            .map_err(|e| bad_request(&format!("entity UID construction failed: {e}")))?;
        let entities = build_entities(claims, &request_ctx, Some(schema))
            .map_err(|e| bad_request(&format!("entity construction failed: {e}")))?;
        (principal, action, resource, entities)
    } else {
        // Legacy path: parse Cedar entity UID strings, use empty entity set.
        let principal = parse_entity_uid(&req.principal).map_err(|e| bad_request(&e))?;
        let action = parse_entity_uid(&req.action).map_err(|e| bad_request(&e))?;
        let resource = parse_entity_uid(&req.resource).map_err(|e| bad_request(&e))?;
        (principal, action, resource, Entities::empty())
    };

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
