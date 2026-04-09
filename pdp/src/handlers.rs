use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema};

use crate::avp;
use crate::entities::{build_entities, build_request_uids, RequestContext};
use crate::models::{
    AuthzRequest, AuthzResponse, BatchAuthzRequest, BatchAuthzResponse, Diagnostics, ErrorResponse,
    HealthResponse, PolicyInfoResponse,
};
use crate::policy::PolicyStore;

/// Application context shared across all handlers.
///
/// Wraps PolicyStore and operational config (admin token, etc.).
/// Implements Deref<Target=PolicyStore> so existing handler code
/// that calls store.load(), store.policy_count(), etc. works unchanged.
pub struct AppContext {
    store: PolicyStore,
    admin_token: Option<String>,
}

impl AppContext {
    pub fn new(store: PolicyStore, admin_token: Option<String>) -> Self {
        Self { store, admin_token }
    }
}

impl std::ops::Deref for AppContext {
    type Target = PolicyStore;
    fn deref(&self) -> &PolicyStore {
        &self.store
    }
}

pub type AppState = Arc<AppContext>;

// ---------------------------------------------------------------------------
// Health probes
// ---------------------------------------------------------------------------

/// Liveness probe: always 200 if the process is listening.
/// Use for Kubernetes livenessProbe.
pub async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Readiness probe: 200 only when policies are loaded and valid.
/// Use for Kubernetes readinessProbe.
pub async fn readyz(State(ctx): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        policies_loaded: ctx.policy_count(),
    })
}

/// Backward-compatible alias for readyz. Existing Docker healthchecks,
/// shell scripts, and integration tests use /health.
pub async fn health(State(ctx): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        policies_loaded: ctx.policy_count(),
    })
}

pub async fn policy_info(State(ctx): State<AppState>) -> Json<PolicyInfoResponse> {
    Json(PolicyInfoResponse {
        policy_count: ctx.policy_count(),
        last_reload_epoch_ms: ctx.last_reload_epoch_ms(),
        schema_hash: ctx.schema_hash(),
    })
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

pub async fn admin_reload(
    State(ctx): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PolicyInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Admin authentication: if PDP_ADMIN_TOKEN is configured, require it.
    if let Some(expected) = &ctx.admin_token {
        let provided = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        match provided {
            Some(token) if token == expected => {} // authenticated
            _ => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "admin endpoint requires Authorization: Bearer <PDP_ADMIN_TOKEN>"
                            .to_string(),
                    }),
                ));
            }
        }
    }
    // If no admin token configured, allow unrestricted (dev mode).
    // main.rs logs a warning at startup when this is the case.

    let old_count = ctx.policy_count();
    match ctx.reload() {
        Ok(new_count) => {
            tracing::info!(old_count, new_count, "manual policy reload successful");
            Ok(Json(PolicyInfoResponse {
                policy_count: new_count,
                last_reload_epoch_ms: ctx.last_reload_epoch_ms(),
                schema_hash: ctx.schema_hash(),
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

// ---------------------------------------------------------------------------
// Request ID middleware
// ---------------------------------------------------------------------------

/// Middleware that propagates or generates X-Request-Id on every request.
/// If the client sends X-Request-Id, it is echoed back. Otherwise a UUID v4
/// is generated. The ID is added to both the response headers and the request
/// extensions (available to handlers via `req.extensions().get::<RequestId>()`).
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

pub async fn request_id_layer(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let mut resp = next.run(req).await;
    if let Ok(val) = id.parse() {
        resp.headers_mut().insert("x-request-id", val);
    }
    resp
}

// ---------------------------------------------------------------------------
// Authorization endpoints
// ---------------------------------------------------------------------------

pub async fn is_authorized(
    State(ctx): State<AppState>,
    Json(req): Json<AuthzRequest>,
) -> Result<Json<AuthzResponse>, (StatusCode, Json<ErrorResponse>)> {
    let state = ctx.load();
    let (policy_set, schema) = state.as_ref();
    let authorizer = Authorizer::new();
    Ok(Json(evaluate_single(&authorizer, &req, policy_set, schema)))
}

pub async fn batch_is_authorized(
    State(ctx): State<AppState>,
    Json(batch): Json<BatchAuthzRequest>,
) -> Result<Json<BatchAuthzResponse>, (StatusCode, Json<ErrorResponse>)> {
    if batch.requests.len() > 100 {
        return Err(bad_request("batch size exceeds maximum of 100"));
    }
    if batch.requests.is_empty() {
        return Ok(Json(BatchAuthzResponse { responses: vec![] }));
    }

    // Load policy state once for the entire batch.
    let state = ctx.load();
    let policy_state = Arc::clone(&state);

    // Rayon fork/join overhead exceeds Cedar eval cost at small batch sizes.
    // Sequential for < 4 items; parallel via rayon for larger batches.
    const RAYON_THRESHOLD: usize = 4;

    let requests = batch.requests;
    let responses = tokio::task::spawn_blocking(move || {
        let (policy_set, schema) = policy_state.as_ref();
        let authorizer = Authorizer::new();
        if requests.len() < RAYON_THRESHOLD {
            requests
                .iter()
                .map(|req| evaluate_single(&authorizer, req, policy_set, schema))
                .collect::<Vec<AuthzResponse>>()
        } else {
            use rayon::prelude::*;
            requests
                .par_iter()
                .map(|req| evaluate_single(&authorizer, req, policy_set, schema))
                .collect::<Vec<AuthzResponse>>()
        }
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
fn evaluate_single(authorizer: &Authorizer, req: &AuthzRequest, policy_set: &PolicySet, schema: &Schema) -> AuthzResponse {
    match evaluate_single_inner(authorizer, req, policy_set, schema) {
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
    authorizer: &Authorizer,
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

// ---------------------------------------------------------------------------
// AVP-compatible authorization endpoints
// ---------------------------------------------------------------------------

/// Single authorization using the Amazon Verified Permissions wire format.
pub async fn avp_is_authorized(
    State(ctx): State<AppState>,
    Json(req): Json<avp::AvpIsAuthorizedRequest>,
) -> Result<Json<avp::AvpIsAuthorizedResponse>, (StatusCode, Json<ErrorResponse>)> {
    let state = ctx.load();
    let (policy_set, schema) = state.as_ref();
    Ok(Json(evaluate_avp_single(&req, policy_set, schema)))
}

/// Batch authorization using the Amazon Verified Permissions wire format.
///
/// Max 30 items. All requests must share either the same principal or the same
/// resource. Entities are shared across all requests (top-level, not per-request).
pub async fn avp_batch_is_authorized(
    State(ctx): State<AppState>,
    Json(req): Json<avp::AvpBatchIsAuthorizedRequest>,
) -> Result<Json<avp::AvpBatchIsAuthorizedResponse>, (StatusCode, Json<ErrorResponse>)> {
    if req.requests.len() > 30 {
        return Err(bad_request("batch size exceeds maximum of 30"));
    }
    if req.requests.is_empty() {
        return Ok(Json(avp::AvpBatchIsAuthorizedResponse { results: vec![] }));
    }
    if let Err(e) = avp::validate_batch_homogeneity(&req.requests) {
        return Err(bad_request(&e));
    }

    let state = ctx.load();
    let policy_state = Arc::clone(&state);
    let entities_def = req.entities;
    let requests = req.requests;

    const RAYON_THRESHOLD: usize = 4;

    let results = tokio::task::spawn_blocking(move || {
        let (policy_set, schema) = policy_state.as_ref();

        // Build shared entities once for the entire batch.
        let entities = match avp::build_cedar_entities(&entities_def, Some(schema)) {
            Ok(e) => Arc::new(e),
            Err(msg) => {
                // Entity construction failed -- return DENY for all items.
                return requests
                    .iter()
                    .map(|item| avp::AvpBatchResult {
                        request: avp::AvpBatchItemEcho {
                            principal: item.principal.clone(),
                            action: item.action.clone(),
                            resource: item.resource.clone(),
                        },
                        decision: "DENY".to_string(),
                        determining_policies: vec![],
                        errors: vec![avp::AvpError {
                            error_description: msg.clone(),
                        }],
                    })
                    .collect();
            }
        };

        if requests.len() < RAYON_THRESHOLD {
            requests
                .iter()
                .map(|item| evaluate_avp_batch_item(item, policy_set, schema, &entities))
                .collect()
        } else {
            use rayon::prelude::*;
            requests
                .par_iter()
                .map(|item| evaluate_avp_batch_item(item, policy_set, schema, &entities))
                .collect()
        }
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

    Ok(Json(avp::AvpBatchIsAuthorizedResponse { results }))
}

/// Evaluate a single AVP-format authorization request.
fn evaluate_avp_single(
    req: &avp::AvpIsAuthorizedRequest,
    policy_set: &PolicySet,
    schema: &Schema,
) -> avp::AvpIsAuthorizedResponse {
    match evaluate_avp_single_inner(req, policy_set, schema) {
        Ok(resp) => resp,
        Err(msg) => avp::AvpIsAuthorizedResponse {
            decision: "DENY".to_string(),
            determining_policies: vec![],
            errors: vec![avp::AvpError {
                error_description: msg,
            }],
        },
    }
}

fn evaluate_avp_single_inner(
    req: &avp::AvpIsAuthorizedRequest,
    policy_set: &PolicySet,
    schema: &Schema,
) -> Result<avp::AvpIsAuthorizedResponse, String> {
    let principal = avp::entity_ref_to_uid(&req.principal)?;
    let action = avp::action_ref_to_uid(&req.action)?;
    let resource = avp::entity_ref_to_uid(&req.resource)?;
    let entities = avp::build_cedar_entities(&req.entities, Some(schema))?;
    let context = avp::build_cedar_context(&req.context)?;

    let cedar_request = Request::new(principal, action, resource, context, Some(schema))
        .map_err(|e| format!("invalid request: {e}"))?;

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&cedar_request, policy_set, &entities);

    Ok(build_avp_response(&response))
}

/// Evaluate a single item within an AVP batch (shared entities).
fn evaluate_avp_batch_item(
    item: &avp::AvpBatchItem,
    policy_set: &PolicySet,
    schema: &Schema,
    entities: &Entities,
) -> avp::AvpBatchResult {
    let echo = avp::AvpBatchItemEcho {
        principal: item.principal.clone(),
        action: item.action.clone(),
        resource: item.resource.clone(),
    };

    let result = (|| -> Result<avp::AvpIsAuthorizedResponse, String> {
        let principal = avp::entity_ref_to_uid(&item.principal)?;
        let action = avp::action_ref_to_uid(&item.action)?;
        let resource = avp::entity_ref_to_uid(&item.resource)?;
        let context = avp::build_cedar_context(&item.context)?;

        let cedar_request = Request::new(principal, action, resource, context, Some(schema))
            .map_err(|e| format!("invalid request: {e}"))?;

        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&cedar_request, policy_set, entities);

        Ok(build_avp_response(&response))
    })();

    match result {
        Ok(resp) => avp::AvpBatchResult {
            request: echo,
            decision: resp.decision,
            determining_policies: resp.determining_policies,
            errors: resp.errors,
        },
        Err(msg) => avp::AvpBatchResult {
            request: echo,
            decision: "DENY".to_string(),
            determining_policies: vec![],
            errors: vec![avp::AvpError {
                error_description: msg,
            }],
        },
    }
}

/// Map a Cedar authorization response to AVP response fields.
fn build_avp_response(response: &cedar_policy::Response) -> avp::AvpIsAuthorizedResponse {
    let decision = match response.decision() {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
    };

    let determining_policies = response
        .diagnostics()
        .reason()
        .map(|id| avp::AvpPolicyRef {
            policy_id: id.to_string(),
        })
        .collect();

    let errors = response
        .diagnostics()
        .errors()
        .map(|e| avp::AvpError {
            error_description: e.to_string(),
        })
        .collect();

    avp::AvpIsAuthorizedResponse {
        decision: decision.to_string(),
        determining_policies,
        errors,
    }
}
