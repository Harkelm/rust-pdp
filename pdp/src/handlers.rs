use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema};

use crate::entities::{build_entities, build_request_uids, RequestContext};
use crate::models::{
    AuthzRequest, AuthzResponse, BatchAuthzRequest, BatchAuthzResponse, Diagnostics, ErrorResponse,
    HealthResponse, PolicyInfoResponse,
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
    let state = store.load();
    let (policy_set, schema) = state.as_ref();
    Ok(Json(evaluate_single(&req, policy_set, schema)))
}

pub async fn batch_is_authorized(
    State(store): State<AppState>,
    Json(batch): Json<BatchAuthzRequest>,
) -> Result<Json<BatchAuthzResponse>, (StatusCode, Json<ErrorResponse>)> {
    if batch.requests.len() > 100 {
        return Err(bad_request("batch size exceeds maximum of 100"));
    }
    if batch.requests.is_empty() {
        return Ok(Json(BatchAuthzResponse { responses: vec![] }));
    }

    // Load policy state once for the entire batch.
    let state = store.load();
    let policy_state = Arc::clone(&state);

    // Use rayon for CPU-bound parallel evaluation instead of spawn_blocking
    // per sub-request, which would saturate tokio's blocking thread pool.
    let requests = batch.requests;
    let responses = tokio::task::spawn_blocking(move || {
        use rayon::prelude::*;
        let (policy_set, schema) = policy_state.as_ref();
        requests
            .par_iter()
            .map(|req| evaluate_single(req, policy_set, schema))
            .collect::<Vec<AuthzResponse>>()
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("batch evaluation failed: {e}"),
            }),
        )
    })?;

    Ok(Json(BatchAuthzResponse { responses }))
}

/// Evaluate a single authorization request against the given policy set and schema.
/// Returns `AuthzResponse` directly -- errors are mapped to Deny with diagnostics.
fn evaluate_single(req: &AuthzRequest, policy_set: &PolicySet, schema: &Schema) -> AuthzResponse {
    match evaluate_single_inner(req, policy_set, schema) {
        Ok(resp) => resp,
        Err(msg) => AuthzResponse {
            decision: "Deny".to_string(),
            diagnostics: Diagnostics {
                reason: vec![],
                errors: vec![msg],
            },
        },
    }
}

/// Inner evaluation that can fail. Errors are surfaced as Deny by the caller.
fn evaluate_single_inner(
    req: &AuthzRequest,
    policy_set: &PolicySet,
    schema: &Schema,
) -> Result<AuthzResponse, String> {
    let (principal, action, resource, entities) = if let Some(claims) = &req.claims {
        // Claims path: treat req.action as HTTP method and req.resource as path.
        let request_ctx = RequestContext {
            method: req.action.clone(),
            path: req.resource.clone(),
            service: None,
        };
        let (principal, action, resource) = build_request_uids(claims, &request_ctx)
            .map_err(|e| format!("entity UID construction failed: {e}"))?;
        let entities = build_entities(claims, &request_ctx, Some(schema))
            .map_err(|e| format!("entity construction failed: {e}"))?;
        (principal, action, resource, entities)
    } else {
        // Legacy path: parse Cedar entity UID strings, use empty entity set.
        let principal = parse_entity_uid(&req.principal).map_err(|e| e.to_string())?;
        let action = parse_entity_uid(&req.action).map_err(|e| e.to_string())?;
        let resource = parse_entity_uid(&req.resource).map_err(|e| e.to_string())?;
        (principal, action, resource, Entities::empty())
    };

    let context = Context::from_json_value(
        serde_json::to_value(&req.context).unwrap_or(serde_json::Value::Object(Default::default())),
        None,
    )
    .map_err(|e| format!("invalid context: {e}"))?;

    let cedar_request = Request::new(principal, action, resource, context, Some(schema))
        .map_err(|e| format!("invalid request: {e}"))?;

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

    Ok(AuthzResponse {
        decision: decision.to_string(),
        diagnostics: Diagnostics { reason, errors },
    })
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
