//! AVP-compatible request/response types and Cedar translation layer.
//!
//! Implements the Amazon Verified Permissions wire format for authorization
//! endpoints. Translates between AVP JSON structures and Cedar SDK types.

use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression, Schema,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

/// Maximum recursion depth for parsing nested typed values (Sets, Records).
const MAX_TYPED_VALUE_DEPTH: u32 = 32;

pub const DECISION_ALLOW: &str = "ALLOW";
pub const DECISION_DENY: &str = "DENY";

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpIsAuthorizedRequest {
    /// Accepted but ignored (single-store deployment).
    #[serde(default)]
    pub policy_store_id: Option<String>,
    pub principal: AvpEntityRef,
    pub action: AvpActionRef,
    pub resource: AvpEntityRef,
    #[serde(default)]
    pub context: Option<AvpContext>,
    #[serde(default)]
    pub entities: Option<AvpEntitySet>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpBatchIsAuthorizedRequest {
    #[serde(default)]
    pub policy_store_id: Option<String>,
    #[serde(default)]
    pub entities: Option<AvpEntitySet>,
    pub requests: Vec<AvpBatchItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpBatchItem {
    pub principal: AvpEntityRef,
    pub action: AvpActionRef,
    pub resource: AvpEntityRef,
    #[serde(default)]
    pub context: Option<AvpContext>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpEntityRef {
    pub entity_type: String,
    pub entity_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpActionRef {
    pub action_type: String,
    pub action_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpContext {
    pub context_map: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpEntitySet {
    pub entity_list: Vec<AvpEntity>,
}

#[derive(Debug, Deserialize)]
pub struct AvpEntity {
    #[serde(alias = "Identifier", alias = "identifier")]
    pub identifier: AvpEntityIdentifier,
    #[serde(alias = "Attributes", alias = "attributes", default)]
    pub attributes: HashMap<String, serde_json::Value>,
    #[serde(alias = "Parents", alias = "parents", default)]
    pub parents: Vec<AvpEntityIdentifier>,
}

#[derive(Debug, Deserialize)]
pub struct AvpEntityIdentifier {
    #[serde(alias = "EntityType", alias = "entityType")]
    pub entity_type: String,
    #[serde(alias = "EntityId", alias = "entityId")]
    pub entity_id: String,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpIsAuthorizedResponse {
    pub decision: String,
    pub determining_policies: Vec<AvpPolicyRef>,
    pub errors: Vec<AvpError>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpBatchIsAuthorizedResponse {
    pub results: Vec<AvpBatchResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpBatchResult {
    pub request: AvpBatchItemEcho,
    pub decision: String,
    pub determining_policies: Vec<AvpPolicyRef>,
    pub errors: Vec<AvpError>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpBatchItemEcho {
    pub principal: AvpEntityRef,
    pub action: AvpActionRef,
    pub resource: AvpEntityRef,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpPolicyRef {
    pub policy_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvpError {
    pub error_description: String,
}

// ---------------------------------------------------------------------------
// Translation: AVP -> Cedar
// ---------------------------------------------------------------------------

/// Convert an AVP entity reference to a Cedar EntityUid.
pub fn entity_ref_to_uid(r: &AvpEntityRef) -> Result<EntityUid, String> {
    make_uid(&r.entity_type, &r.entity_id)
}

/// Convert an AVP action reference to a Cedar EntityUid.
pub fn action_ref_to_uid(r: &AvpActionRef) -> Result<EntityUid, String> {
    make_uid(&r.action_type, &r.action_id)
}

/// Parse an AVP typed value wrapper into a Cedar RestrictedExpression.
///
/// Supported wrappers: String, Boolean, Long, Set, Record, EntityIdentifier.
pub fn parse_typed_value(val: &serde_json::Value) -> Result<RestrictedExpression, String> {
    parse_typed_value_inner(val, 0)
}

fn parse_typed_value_inner(val: &serde_json::Value, depth: u32) -> Result<RestrictedExpression, String> {
    if depth > MAX_TYPED_VALUE_DEPTH {
        return Err("typed value nesting exceeds maximum depth".to_string());
    }

    let obj = val
        .as_object()
        .ok_or_else(|| format!("expected typed value object, got: {val}"))?;

    if let Some(s) = obj.get("String") {
        return Ok(RestrictedExpression::new_string(
            s.as_str()
                .ok_or("String value must be a string")?
                .to_string(),
        ));
    }
    if let Some(b) = obj.get("Boolean") {
        return Ok(RestrictedExpression::new_bool(
            b.as_bool().ok_or("Boolean value must be a bool")?,
        ));
    }
    if let Some(n) = obj.get("Long") {
        return Ok(RestrictedExpression::new_long(
            n.as_i64().ok_or("Long value must be an integer")?,
        ));
    }
    if let Some(set) = obj.get("Set") {
        let items = set
            .as_array()
            .ok_or("Set value must be an array")?
            .iter()
            .map(|v| parse_typed_value_inner(v, depth + 1))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(RestrictedExpression::new_set(items));
    }
    if let Some(rec) = obj.get("Record") {
        let fields = rec
            .as_object()
            .ok_or("Record value must be an object")?
            .iter()
            .map(|(k, v)| {
                parse_typed_value_inner(v, depth + 1).map(|expr| (k.clone(), expr))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return RestrictedExpression::new_record(fields).map_err(|e| e.to_string());
    }
    if let Some(eid) = obj.get("EntityIdentifier") {
        let eo = eid
            .as_object()
            .ok_or("EntityIdentifier value must be an object")?;
        let et = eo
            .get("EntityType")
            .or_else(|| eo.get("entityType"))
            .and_then(|v| v.as_str())
            .ok_or("EntityIdentifier missing EntityType")?;
        let ei = eo
            .get("EntityId")
            .or_else(|| eo.get("entityId"))
            .and_then(|v| v.as_str())
            .ok_or("EntityIdentifier missing EntityId")?;
        let tn = EntityTypeName::from_str(et)
            .map_err(|e| format!("invalid entity type in EntityIdentifier: {e}"))?;
        let uid = EntityUid::from_type_name_and_id(tn, EntityId::new(ei));
        return Ok(RestrictedExpression::new_entity_uid(uid));
    }

    Err(format!("unrecognized AVP typed value: {val}"))
}

/// Convert an AVP typed value to plain Cedar JSON (for Context::from_json_value).
///
/// Unlike `parse_typed_value` which produces RestrictedExpression, this produces
/// serde_json::Value compatible with Cedar's JSON context format.
pub fn typed_value_to_cedar_json(val: &serde_json::Value) -> Result<serde_json::Value, String> {
    typed_value_to_cedar_json_inner(val, 0)
}

fn typed_value_to_cedar_json_inner(val: &serde_json::Value, depth: u32) -> Result<serde_json::Value, String> {
    if depth > MAX_TYPED_VALUE_DEPTH {
        return Err("typed value nesting exceeds maximum depth".to_string());
    }

    let obj = val
        .as_object()
        .ok_or_else(|| format!("expected typed value object, got: {val}"))?;

    if let Some(s) = obj.get("String") {
        return Ok(s.clone());
    }
    if let Some(b) = obj.get("Boolean") {
        return Ok(b.clone());
    }
    if let Some(n) = obj.get("Long") {
        return Ok(n.clone());
    }
    if let Some(set) = obj.get("Set") {
        let items = set
            .as_array()
            .ok_or("Set value must be an array")?
            .iter()
            .map(|v| typed_value_to_cedar_json_inner(v, depth + 1))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(serde_json::Value::Array(items));
    }
    if let Some(rec) = obj.get("Record") {
        let fields = rec
            .as_object()
            .ok_or("Record value must be an object")?
            .iter()
            .map(|(k, v)| {
                typed_value_to_cedar_json_inner(v, depth + 1).map(|j| (k.clone(), j))
            })
            .collect::<Result<serde_json::Map<String, serde_json::Value>, _>>()?;
        return Ok(serde_json::Value::Object(fields));
    }
    if let Some(eid) = obj.get("EntityIdentifier") {
        let eo = eid
            .as_object()
            .ok_or("EntityIdentifier value must be an object")?;
        let et = eo
            .get("EntityType")
            .or_else(|| eo.get("entityType"))
            .and_then(|v| v.as_str())
            .ok_or("EntityIdentifier missing EntityType")?;
        let ei = eo
            .get("EntityId")
            .or_else(|| eo.get("entityId"))
            .and_then(|v| v.as_str())
            .ok_or("EntityIdentifier missing EntityId")?;
        return Ok(serde_json::json!({
            "__entity": { "type": et, "id": ei }
        }));
    }

    Err(format!("unrecognized AVP typed value: {val}"))
}

/// Convert an AVP entity list into Cedar Entities.
pub fn build_cedar_entities(
    entity_set: &Option<AvpEntitySet>,
    schema: Option<&Schema>,
) -> Result<Entities, String> {
    let list = match entity_set {
        None => return Entities::from_entities(Vec::<Entity>::new(), schema)
            .map_err(|e| format!("entity construction failed: {e}")),
        Some(es) => &es.entity_list,
    };

    let mut cedar_entities = Vec::with_capacity(list.len());
    for avp_entity in list {
        let uid = identifier_to_uid(&avp_entity.identifier)?;

        let mut parents = HashSet::new();
        for parent in &avp_entity.parents {
            parents.insert(identifier_to_uid(parent)?);
        }

        if avp_entity.attributes.is_empty() {
            cedar_entities.push(Entity::new_no_attrs(uid, parents));
        } else {
            let mut attrs = HashMap::new();
            for (key, val) in &avp_entity.attributes {
                attrs.insert(
                    key.clone(),
                    parse_typed_value(val)
                        .map_err(|e| format!("attribute '{key}': {e}"))?,
                );
            }
            cedar_entities.push(
                Entity::new(uid, attrs, parents)
                    .map_err(|e| format!("entity construction failed: {e}"))?,
            );
        }
    }

    Entities::from_entities(cedar_entities, schema)
        .map_err(|e| format!("entity set construction failed: {e}"))
}

/// Convert an AVP contextMap into a Cedar Context.
pub fn build_cedar_context(ctx: &Option<AvpContext>) -> Result<Context, String> {
    let json_obj = match ctx {
        None => serde_json::Value::Object(Default::default()),
        Some(avp_ctx) => {
            let mut map = serde_json::Map::new();
            for (key, val) in &avp_ctx.context_map {
                map.insert(
                    key.clone(),
                    typed_value_to_cedar_json(val)
                        .map_err(|e| format!("context key '{key}': {e}"))?,
                );
            }
            serde_json::Value::Object(map)
        }
    };
    Context::from_json_value(json_obj, None).map_err(|e| format!("invalid context: {e}"))
}

/// Validate that all batch requests share either the same principal or the same resource.
pub fn validate_batch_homogeneity(requests: &[AvpBatchItem]) -> Result<(), String> {
    if requests.len() <= 1 {
        return Ok(());
    }
    let first = &requests[0];
    let all_same_principal = requests.iter().all(|r| {
        r.principal.entity_type == first.principal.entity_type
            && r.principal.entity_id == first.principal.entity_id
    });
    let all_same_resource = requests.iter().all(|r| {
        r.resource.entity_type == first.resource.entity_type
            && r.resource.entity_id == first.resource.entity_id
    });
    if !all_same_principal && !all_same_resource {
        return Err(
            "batch requests must share either the same principal or the same resource"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a Cedar EntityUid from type name and id strings.
fn make_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, String> {
    let tn = EntityTypeName::from_str(entity_type)
        .map_err(|e| format!("invalid entity type '{entity_type}': {e}"))?;
    Ok(EntityUid::from_type_name_and_id(tn, EntityId::new(entity_id)))
}

fn identifier_to_uid(id: &AvpEntityIdentifier) -> Result<EntityUid, String> {
    make_uid(&id.entity_type, &id.entity_id)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entity_ref_to_uid_valid() {
        let r = AvpEntityRef {
            entity_type: "ApiGateway::User".into(),
            entity_id: "alice".into(),
        };
        let uid = entity_ref_to_uid(&r).unwrap();
        assert_eq!(uid.to_string(), r#"ApiGateway::User::"alice""#);
    }

    #[test]
    fn action_ref_to_uid_valid() {
        let r = AvpActionRef {
            action_type: "ApiGateway::Action".into(),
            action_id: "read".into(),
        };
        let uid = action_ref_to_uid(&r).unwrap();
        assert_eq!(uid.to_string(), r#"ApiGateway::Action::"read""#);
    }

    #[test]
    fn parse_typed_string() {
        let val = json!({"String": "hello"});
        parse_typed_value(&val).unwrap();
    }

    #[test]
    fn parse_typed_boolean() {
        let val = json!({"Boolean": true});
        parse_typed_value(&val).unwrap();
    }

    #[test]
    fn parse_typed_long() {
        let val = json!({"Long": 42});
        parse_typed_value(&val).unwrap();
    }

    #[test]
    fn parse_typed_set() {
        let val = json!({"Set": [{"String": "a"}, {"String": "b"}]});
        parse_typed_value(&val).unwrap();
    }

    #[test]
    fn parse_typed_record() {
        let val = json!({"Record": {"name": {"String": "alice"}, "age": {"Long": 30}}});
        parse_typed_value(&val).unwrap();
    }

    #[test]
    fn parse_typed_entity_identifier() {
        let val = json!({"EntityIdentifier": {"EntityType": "User", "EntityId": "alice"}});
        parse_typed_value(&val).unwrap();
    }

    #[test]
    fn parse_typed_unknown_wrapper_fails() {
        let val = json!({"Float": 3.14});
        let err = parse_typed_value(&val).unwrap_err();
        assert!(err.contains("unrecognized AVP typed value"));
    }

    #[test]
    fn parse_typed_depth_limit() {
        // Build a deeply nested Set structure
        let mut val = json!({"String": "leaf"});
        for _ in 0..40 {
            val = json!({"Set": [val]});
        }
        let err = parse_typed_value(&val).unwrap_err();
        assert!(err.contains("nesting exceeds maximum depth"));
    }

    #[test]
    fn typed_value_to_cedar_json_string() {
        let val = json!({"String": "hello"});
        assert_eq!(typed_value_to_cedar_json(&val).unwrap(), json!("hello"));
    }

    #[test]
    fn typed_value_to_cedar_json_boolean() {
        let val = json!({"Boolean": false});
        assert_eq!(typed_value_to_cedar_json(&val).unwrap(), json!(false));
    }

    #[test]
    fn typed_value_to_cedar_json_set() {
        let val = json!({"Set": [{"Long": 1}, {"Long": 2}]});
        assert_eq!(typed_value_to_cedar_json(&val).unwrap(), json!([1, 2]));
    }

    #[test]
    fn typed_value_to_cedar_json_entity() {
        let val = json!({"EntityIdentifier": {"EntityType": "User", "EntityId": "bob"}});
        let result = typed_value_to_cedar_json(&val).unwrap();
        assert_eq!(result, json!({"__entity": {"type": "User", "id": "bob"}}));
    }

    #[test]
    fn build_cedar_entities_empty() {
        let entities = build_cedar_entities(&None, None).unwrap();
        assert!(entities.iter().next().is_none());
    }

    #[test]
    fn build_cedar_entities_with_hierarchy() {
        let entity_set = AvpEntitySet {
            entity_list: vec![
                AvpEntity {
                    identifier: AvpEntityIdentifier {
                        entity_type: "User".into(),
                        entity_id: "alice".into(),
                    },
                    attributes: HashMap::new(),
                    parents: vec![AvpEntityIdentifier {
                        entity_type: "Group".into(),
                        entity_id: "admins".into(),
                    }],
                },
                AvpEntity {
                    identifier: AvpEntityIdentifier {
                        entity_type: "Group".into(),
                        entity_id: "admins".into(),
                    },
                    attributes: HashMap::new(),
                    parents: vec![],
                },
            ],
        };
        let entities = build_cedar_entities(&Some(entity_set), None).unwrap();
        // Should have both entities
        let count = entities.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn build_cedar_context_empty() {
        let ctx = build_cedar_context(&None).unwrap();
        // Empty context should work
        let _ = ctx;
    }

    #[test]
    fn build_cedar_context_with_values() {
        let avp_ctx = AvpContext {
            context_map: HashMap::from([
                ("ip".into(), json!({"String": "192.168.1.1"})),
                ("authenticated".into(), json!({"Boolean": true})),
            ]),
        };
        build_cedar_context(&Some(avp_ctx)).unwrap();
    }

    #[test]
    fn validate_batch_homogeneity_empty() {
        validate_batch_homogeneity(&[]).unwrap();
    }

    #[test]
    fn validate_batch_homogeneity_single() {
        let items = vec![AvpBatchItem {
            principal: AvpEntityRef {
                entity_type: "User".into(),
                entity_id: "alice".into(),
            },
            action: AvpActionRef {
                action_type: "Action".into(),
                action_id: "read".into(),
            },
            resource: AvpEntityRef {
                entity_type: "Resource".into(),
                entity_id: "doc1".into(),
            },
            context: None,
        }];
        validate_batch_homogeneity(&items).unwrap();
    }

    #[test]
    fn validate_batch_homogeneity_same_principal() {
        let items = vec![
            AvpBatchItem {
                principal: AvpEntityRef { entity_type: "User".into(), entity_id: "alice".into() },
                action: AvpActionRef { action_type: "Action".into(), action_id: "read".into() },
                resource: AvpEntityRef { entity_type: "Res".into(), entity_id: "doc1".into() },
                context: None,
            },
            AvpBatchItem {
                principal: AvpEntityRef { entity_type: "User".into(), entity_id: "alice".into() },
                action: AvpActionRef { action_type: "Action".into(), action_id: "write".into() },
                resource: AvpEntityRef { entity_type: "Res".into(), entity_id: "doc2".into() },
                context: None,
            },
        ];
        validate_batch_homogeneity(&items).unwrap();
    }

    #[test]
    fn validate_batch_homogeneity_same_resource() {
        let items = vec![
            AvpBatchItem {
                principal: AvpEntityRef { entity_type: "User".into(), entity_id: "alice".into() },
                action: AvpActionRef { action_type: "Action".into(), action_id: "read".into() },
                resource: AvpEntityRef { entity_type: "Res".into(), entity_id: "doc1".into() },
                context: None,
            },
            AvpBatchItem {
                principal: AvpEntityRef { entity_type: "User".into(), entity_id: "bob".into() },
                action: AvpActionRef { action_type: "Action".into(), action_id: "read".into() },
                resource: AvpEntityRef { entity_type: "Res".into(), entity_id: "doc1".into() },
                context: None,
            },
        ];
        validate_batch_homogeneity(&items).unwrap();
    }

    #[test]
    fn validate_batch_homogeneity_violation() {
        let items = vec![
            AvpBatchItem {
                principal: AvpEntityRef { entity_type: "User".into(), entity_id: "alice".into() },
                action: AvpActionRef { action_type: "Action".into(), action_id: "read".into() },
                resource: AvpEntityRef { entity_type: "Res".into(), entity_id: "doc1".into() },
                context: None,
            },
            AvpBatchItem {
                principal: AvpEntityRef { entity_type: "User".into(), entity_id: "bob".into() },
                action: AvpActionRef { action_type: "Action".into(), action_id: "read".into() },
                resource: AvpEntityRef { entity_type: "Res".into(), entity_id: "doc2".into() },
                context: None,
            },
        ];
        let err = validate_batch_homogeneity(&items).unwrap_err();
        assert!(err.contains("must share either the same principal or the same resource"));
    }
}
