use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    entities_errors::EntitiesError, Entities, Entity, EntityAttrEvaluationError, EntityId,
    EntityTypeName, EntityUid, RestrictedExpression, Schema,
};
use serde::Deserialize;

/// JWT claims extracted by the Kong plugin or PDP from the request.
#[derive(Debug, Deserialize, Default)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub subscription_tier: Option<String>,
    #[serde(default)]
    pub suspended: Option<bool>,
    #[serde(default)]
    pub allowed_scopes: Option<Vec<String>>,
}

/// Request context for building Action and Resource entities.
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub service: Option<String>,
}

/// Map HTTP method to Cedar action name per schema.
pub fn method_to_action(method: &str) -> &str {
    match method.to_uppercase().as_str() {
        "GET" => "read",
        "HEAD" => "read",
        "POST" => "write",
        "PUT" => "write",
        "PATCH" => "write",
        "DELETE" => "delete",
        "OPTIONS" => "read",
        _ => "read",
    }
}

fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, String> {
    let tn = EntityTypeName::from_str(type_name)
        .map_err(|e| format!("invalid entity type name '{type_name}': {e}"))?;
    Ok(EntityUid::from_type_name_and_id(tn, EntityId::new(id)))
}

/// Error type for entity construction failures.
#[derive(Debug)]
pub enum EntityBuildError {
    TypeName(String),
    Attr(EntityAttrEvaluationError),
    Entities(EntitiesError),
}

impl std::fmt::Display for EntityBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityBuildError::TypeName(s) => write!(f, "type name error: {s}"),
            EntityBuildError::Attr(e) => write!(f, "attribute evaluation error: {e}"),
            EntityBuildError::Entities(e) => write!(f, "entities error: {e}"),
        }
    }
}

impl std::error::Error for EntityBuildError {}

impl From<EntityAttrEvaluationError> for EntityBuildError {
    fn from(e: EntityAttrEvaluationError) -> Self {
        EntityBuildError::Attr(e)
    }
}

impl From<EntitiesError> for EntityBuildError {
    fn from(e: EntitiesError) -> Self {
        EntityBuildError::Entities(e)
    }
}

/// Build the complete Cedar Entities set from claims and request context.
///
/// Entity layout:
/// - One `ApiGateway::Role` per role in claims.roles (no attributes, no parents)
/// - One `ApiGateway::Organization` for claims.org (no attributes, no parents)
/// - One `ApiGateway::User` with all claim attributes, parents = roles + org
/// - One `ApiGateway::ApiResource` derived from request path
pub fn build_entities(
    claims: &Claims,
    request_ctx: &RequestContext,
    schema: Option<&Schema>,
) -> Result<Entities, EntityBuildError> {
    let mut entity_vec: Vec<Entity> = Vec::new();

    // --- Role entities ---
    let mut user_parents: HashSet<EntityUid> = HashSet::new();

    if let Some(roles) = &claims.roles {
        for role_name in roles {
            let role_uid =
                entity_uid("ApiGateway::Role", role_name).map_err(EntityBuildError::TypeName)?;
            user_parents.insert(role_uid.clone());
            let role_entity = Entity::new_no_attrs(role_uid, HashSet::new());
            entity_vec.push(role_entity);
        }
    }

    // --- Organization entity ---
    if let Some(org) = &claims.org {
        let org_uid =
            entity_uid("ApiGateway::Organization", org).map_err(EntityBuildError::TypeName)?;
        user_parents.insert(org_uid.clone());
        let org_entity = Entity::new_no_attrs(org_uid, HashSet::new());
        entity_vec.push(org_entity);
    }

    // --- User entity ---
    let user_uid =
        entity_uid("ApiGateway::User", &claims.sub).map_err(EntityBuildError::TypeName)?;

    let mut user_attrs: HashMap<String, RestrictedExpression> = HashMap::new();

    user_attrs.insert(
        "email".to_string(),
        RestrictedExpression::new_string(claims.email.clone().unwrap_or_default()),
    );
    user_attrs.insert(
        "department".to_string(),
        RestrictedExpression::new_string(claims.department.clone().unwrap_or_default()),
    );
    user_attrs.insert(
        "org".to_string(),
        RestrictedExpression::new_string(claims.org.clone().unwrap_or_default()),
    );
    user_attrs.insert(
        "subscription_tier".to_string(),
        RestrictedExpression::new_string(
            claims
                .subscription_tier
                .clone()
                .unwrap_or_else(|| "basic".to_string()),
        ),
    );
    user_attrs.insert(
        "suspended".to_string(),
        RestrictedExpression::new_bool(claims.suspended.unwrap_or(false)),
    );

    let scope_exprs: Vec<RestrictedExpression> = claims
        .allowed_scopes
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| RestrictedExpression::new_string(s.clone()))
        .collect();
    user_attrs.insert(
        "allowed_scopes".to_string(),
        RestrictedExpression::new_set(scope_exprs),
    );

    let user_entity = Entity::new(user_uid, user_attrs, user_parents)?;
    entity_vec.push(user_entity);

    // --- ApiResource entity ---
    let resource_uid = entity_uid("ApiGateway::ApiResource", &request_ctx.path)
        .map_err(EntityBuildError::TypeName)?;

    let mut resource_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    resource_attrs.insert(
        "service".to_string(),
        RestrictedExpression::new_string(
            request_ctx
                .service
                .clone()
                .unwrap_or_else(|| "default".to_string()),
        ),
    );
    resource_attrs.insert(
        "path_pattern".to_string(),
        RestrictedExpression::new_string(request_ctx.path.clone()),
    );
    resource_attrs.insert(
        "department".to_string(),
        RestrictedExpression::new_string(String::new()),
    );
    resource_attrs.insert(
        "classification".to_string(),
        RestrictedExpression::new_string("internal".to_string()),
    );
    resource_attrs.insert(
        "owner_org".to_string(),
        RestrictedExpression::new_string(claims.org.clone().unwrap_or_default()),
    );

    let resource_entity = Entity::new(resource_uid, resource_attrs, HashSet::new())?;
    entity_vec.push(resource_entity);

    let entities = Entities::from_entities(entity_vec, schema)?;
    Ok(entities)
}

/// Build entity UIDs for the Cedar Request (principal, action, resource).
///
/// Maps HTTP method to schema action name per `method_to_action`.
pub fn build_request_uids(
    claims: &Claims,
    request_ctx: &RequestContext,
) -> Result<(EntityUid, EntityUid, EntityUid), String> {
    let principal = entity_uid("ApiGateway::User", &claims.sub)?;
    let action = entity_uid(
        "ApiGateway::Action",
        method_to_action(&request_ctx.method),
    )?;
    let resource = entity_uid("ApiGateway::ApiResource", &request_ctx.path)?;
    Ok((principal, action, resource))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_claims() -> Claims {
        Claims {
            sub: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            department: Some("engineering".to_string()),
            org: Some("acme".to_string()),
            roles: Some(vec!["admin".to_string(), "viewer".to_string()]),
            subscription_tier: Some("enterprise".to_string()),
            suspended: Some(false),
            allowed_scopes: Some(vec!["internal".to_string()]),
        }
    }

    fn get_ctx() -> RequestContext {
        RequestContext {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            service: None,
        }
    }

    #[test]
    fn test_jwt_with_roles_produces_user_with_role_parents() {
        let claims = full_claims();
        let ctx = get_ctx();

        // Build without schema (schema validation requires loaded schema files).
        let entities = build_entities(&claims, &ctx, None).expect("should build entities");

        // Verify entity count: User + 2 Roles + 1 Organization + 1 ApiResource = 5
        let user_uid = entity_uid("ApiGateway::User", "alice").unwrap();
        let admin_uid = entity_uid("ApiGateway::Role", "admin").unwrap();
        let viewer_uid = entity_uid("ApiGateway::Role", "viewer").unwrap();
        let org_uid = entity_uid("ApiGateway::Organization", "acme").unwrap();
        let resource_uid = entity_uid("ApiGateway::ApiResource", "/api/test").unwrap();

        // All five entities must be present.
        assert!(
            entities.get(&user_uid).is_some(),
            "User entity must be present"
        );
        assert!(
            entities.get(&admin_uid).is_some(),
            "admin Role entity must be present"
        );
        assert!(
            entities.get(&viewer_uid).is_some(),
            "viewer Role entity must be present"
        );
        assert!(
            entities.get(&org_uid).is_some(),
            "Organization entity must be present"
        );
        assert!(
            entities.get(&resource_uid).is_some(),
            "ApiResource entity must be present"
        );

        // Verify role parentage via ancestor check.
        assert!(
            entities.is_ancestor_of(&admin_uid, &user_uid),
            "admin must be an ancestor of User (i.e., User in [Role])"
        );
        assert!(
            entities.is_ancestor_of(&viewer_uid, &user_uid),
            "viewer must be an ancestor of User"
        );
        assert!(
            entities.is_ancestor_of(&org_uid, &user_uid),
            "Organization must be an ancestor of User"
        );
    }

    #[test]
    fn test_missing_optional_claims_no_panic() {
        let claims = Claims {
            sub: "bob".to_string(),
            ..Default::default()
        };
        let ctx = RequestContext {
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            service: None,
        };

        let entities = build_entities(&claims, &ctx, None)
            .expect("should not panic or error with missing optional claims");

        // Minimum: User + ApiResource = 2 entities (no roles, no org)
        let user_uid = entity_uid("ApiGateway::User", "bob").unwrap();
        let resource_uid = entity_uid("ApiGateway::ApiResource", "/api/data").unwrap();

        assert!(
            entities.get(&user_uid).is_some(),
            "User must be present even with missing claims"
        );
        assert!(
            entities.get(&resource_uid).is_some(),
            "ApiResource must be present"
        );
    }

    #[test]
    fn test_action_and_resource_uids() {
        let claims = Claims {
            sub: "test".to_string(),
            ..Default::default()
        };
        let ctx = RequestContext {
            method: "DELETE".to_string(),
            path: "/api/items/42".to_string(),
            service: None,
        };

        let (principal, action, resource) =
            build_request_uids(&claims, &ctx).expect("should build UIDs");

        assert_eq!(
            principal.to_string(),
            r#"ApiGateway::User::"test""#,
            "principal UID must match"
        );
        assert_eq!(
            action.to_string(),
            r#"ApiGateway::Action::"delete""#,
            "DELETE must map to delete action"
        );
        assert_eq!(
            resource.to_string(),
            r#"ApiGateway::ApiResource::"/api/items/42""#,
            "resource UID must match path"
        );
    }

    #[test]
    fn test_method_to_action_mapping() {
        assert_eq!(method_to_action("GET"), "read");
        assert_eq!(method_to_action("HEAD"), "read");
        assert_eq!(method_to_action("POST"), "write");
        assert_eq!(method_to_action("PUT"), "write");
        assert_eq!(method_to_action("PATCH"), "write");
        assert_eq!(method_to_action("DELETE"), "delete");
        assert_eq!(method_to_action("OPTIONS"), "read");
        assert_eq!(method_to_action("UNKNOWN"), "read", "unknown methods default to read");
    }

    #[test]
    fn test_resource_defaults_with_service_none() {
        let claims = Claims {
            sub: "carol".to_string(),
            org: Some("beta-corp".to_string()),
            ..Default::default()
        };
        let ctx = RequestContext {
            method: "GET".to_string(),
            path: "/health".to_string(),
            service: None,
        };

        let entities =
            build_entities(&claims, &ctx, None).expect("should build with service=None");

        let resource_uid = entity_uid("ApiGateway::ApiResource", "/health").unwrap();
        assert!(
            entities.get(&resource_uid).is_some(),
            "resource must be present"
        );
    }

    #[test]
    fn test_empty_roles_list_no_role_entities() {
        let claims = Claims {
            sub: "dave".to_string(),
            roles: Some(vec![]), // explicit empty list
            ..Default::default()
        };
        let ctx = RequestContext {
            method: "GET".to_string(),
            path: "/api/v1/status".to_string(),
            service: None,
        };

        let entities = build_entities(&claims, &ctx, None).expect("should build with empty roles");

        let user_uid = entity_uid("ApiGateway::User", "dave").unwrap();
        assert!(
            entities.get(&user_uid).is_some(),
            "User must exist even with empty roles list"
        );
    }
}
