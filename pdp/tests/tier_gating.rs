//! Subscription tier gating correctness tests.
//!
//! Exercises the tier-enterprise-access, tier-professional-access, and
//! tier-basic-access policies against Feature entities with required_tier
//! attributes.
//!
//! NOTE: These test at the Cedar evaluation level, not through HTTP, because
//! the current claims-path entity builder (entities.rs) only constructs
//! ApiResource entities. Feature entities require a separate construction
//! path that does not yet exist. This is a known design gap -- tier gating
//! policies are defined but unreachable via the claims path.

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

const PROD_SCHEMA: &str = include_str!("../../policies/api_gateway.cedarschema");
const POLICY_TIER: &str = include_str!("../../policies/subscription_tier_gating.cedar");
const POLICY_SUSPENDED: &str = include_str!("../../policies/suspended_account_deny.cedar");

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

fn prod_schema() -> Schema {
    Schema::from_cedarschema_str(PROD_SCHEMA)
        .expect("valid schema")
        .0
}

/// Build a User entity with the given subscription tier.
fn make_user(id: &str, tier: &str, suspended: bool) -> (Entity, Entity) {
    let org_uid = make_uid("ApiGateway::Organization", "acme");
    let org_entity = Entity::new_no_attrs(org_uid.clone(), HashSet::new());

    let user_uid = make_uid("ApiGateway::User", id);
    let mut parents = HashSet::new();
    parents.insert(org_uid);

    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert("email".into(), RestrictedExpression::new_string(format!("{id}@example.com")));
    attrs.insert("department".into(), RestrictedExpression::new_string("engineering".into()));
    attrs.insert("org".into(), RestrictedExpression::new_string("acme".into()));
    attrs.insert("subscription_tier".into(), RestrictedExpression::new_string(tier.into()));
    attrs.insert("suspended".into(), RestrictedExpression::new_bool(suspended));
    attrs.insert("allowed_scopes".into(), RestrictedExpression::new_set(vec![]));

    let user_entity = Entity::new(user_uid, attrs, parents).expect("valid user");
    (user_entity, org_entity)
}

/// Build a Feature entity with the given required tier.
fn make_feature(id: &str, required_tier: &str) -> Entity {
    let uid = make_uid("ApiGateway::Feature", id);
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    attrs.insert("required_tier".into(), RestrictedExpression::new_string(required_tier.into()));
    Entity::new(uid, attrs, HashSet::new()).expect("valid feature")
}

/// Evaluate a tier gating request and return (decision, determining_policies).
fn eval_tier(
    user_id: &str,
    user_tier: &str,
    feature_id: &str,
    feature_tier: &str,
    suspended: bool,
    include_forbid: bool,
) -> (String, Vec<String>) {
    let schema = prod_schema();
    let mut policy_src = POLICY_TIER.to_string();
    if include_forbid {
        policy_src.push('\n');
        policy_src.push_str(POLICY_SUSPENDED);
    }
    let policies: PolicySet = policy_src.parse().expect("valid policies");
    let authorizer = Authorizer::new();

    let (user_entity, org_entity) = make_user(user_id, user_tier, suspended);
    let feature_entity = make_feature(feature_id, feature_tier);

    let entities = Entities::from_entities(
        vec![user_entity, org_entity, feature_entity],
        Some(&schema),
    )
    .expect("valid entities");

    let request = Request::new(
        make_uid("ApiGateway::User", user_id),
        make_uid("ApiGateway::Action", "read"),
        make_uid("ApiGateway::Feature", feature_id),
        Context::empty(),
        Some(&schema),
    )
    .expect("valid request");

    let response = authorizer.is_authorized(&request, &policies, &entities);
    let decision = match response.decision() {
        cedar_policy::Decision::Allow => "Allow",
        cedar_policy::Decision::Deny => "Deny",
    };
    let reasons: Vec<String> = response.diagnostics().reason().map(|id| id.to_string()).collect();
    (decision.to_string(), reasons)
}

// ===========================================================================
// Enterprise tier access
// ===========================================================================

#[test]
fn test_enterprise_user_accesses_enterprise_feature() {
    let (decision, reasons) = eval_tier("ent-user", "enterprise", "adv-analytics", "enterprise", false, false);
    assert_eq!(decision, "Allow");
    assert_eq!(
        reasons.len(), 1,
        "enterprise user + enterprise feature should match exactly 1 tier policy, got: {reasons:?}"
    );
}

#[test]
fn test_enterprise_user_accesses_professional_feature() {
    let (decision, reasons) = eval_tier("ent-user", "enterprise", "dashboards", "professional", false, false);
    assert_eq!(decision, "Allow");
    assert_eq!(
        reasons.len(), 1,
        "enterprise user + professional feature should match exactly 1 tier policy, got: {reasons:?}"
    );
}

#[test]
fn test_enterprise_user_accesses_basic_feature() {
    let (decision, reasons) = eval_tier("ent-user", "enterprise", "status-page", "basic", false, false);
    assert_eq!(decision, "Allow");
    // basic-access fires for any authenticated user when resource.required_tier == "basic"
    assert_eq!(
        reasons.len(), 1,
        "enterprise user + basic feature should match exactly 1 tier policy, got: {reasons:?}"
    );
}

// ===========================================================================
// Professional tier access
// ===========================================================================

#[test]
fn test_professional_user_denied_enterprise_feature() {
    let (decision, _) = eval_tier("pro-user", "professional", "adv-analytics", "enterprise", false, false);
    assert_eq!(
        decision, "Deny",
        "professional user must be denied enterprise-tier features"
    );
}

#[test]
fn test_professional_user_accesses_professional_feature() {
    let (decision, reasons) = eval_tier("pro-user", "professional", "dashboards", "professional", false, false);
    assert_eq!(decision, "Allow");
    assert_eq!(
        reasons.len(), 1,
        "professional user + professional feature should match exactly 1 tier policy, got: {reasons:?}"
    );
}

#[test]
fn test_professional_user_accesses_basic_feature() {
    let (decision, _) = eval_tier("pro-user", "professional", "status-page", "basic", false, false);
    assert_eq!(decision, "Allow");
}

// ===========================================================================
// Basic tier access
// ===========================================================================

#[test]
fn test_basic_user_denied_enterprise_feature() {
    let (decision, _) = eval_tier("basic-user", "basic", "adv-analytics", "enterprise", false, false);
    assert_eq!(decision, "Deny");
}

#[test]
fn test_basic_user_denied_professional_feature() {
    let (decision, _) = eval_tier("basic-user", "basic", "dashboards", "professional", false, false);
    assert_eq!(decision, "Deny");
}

#[test]
fn test_basic_user_accesses_basic_feature() {
    let (decision, reasons) = eval_tier("basic-user", "basic", "status-page", "basic", false, false);
    assert_eq!(decision, "Allow");
    assert_eq!(
        reasons.len(), 1,
        "basic user + basic feature should match exactly 1 tier policy, got: {reasons:?}"
    );
}

// ===========================================================================
// Tier + forbid interaction: suspended user denied even with enterprise tier
// ===========================================================================

#[test]
fn test_suspended_enterprise_user_denied_feature() {
    let (decision, _) = eval_tier(
        "suspended-ent", "enterprise", "adv-analytics", "enterprise", true, true,
    );
    assert_eq!(
        decision, "Deny",
        "suspended user must be denied even with enterprise tier (forbid override)"
    );
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn test_unknown_tier_denied_all_features() {
    // A user with a tier value not matching any policy condition
    for feature_tier in &["enterprise", "professional", "basic"] {
        let (decision, _) = eval_tier("unknown-tier", "trial", "feature-x", feature_tier, false, false);
        // "trial" doesn't match enterprise or professional tier checks.
        // For basic features, tier-basic-access has no tier check on principal --
        // it only checks resource.required_tier == "basic".
        if *feature_tier == "basic" {
            assert_eq!(
                decision, "Allow",
                "tier-basic-access permits any authenticated user for basic features"
            );
        } else {
            assert_eq!(
                decision, "Deny",
                "unknown tier 'trial' must be denied for {feature_tier} features"
            );
        }
    }
}

#[test]
fn test_empty_tier_denied_enterprise_and_professional() {
    let (decision, _) = eval_tier("empty-tier", "", "ent-feature", "enterprise", false, false);
    assert_eq!(decision, "Deny", "empty tier must be denied enterprise features");

    let (decision, _) = eval_tier("empty-tier", "", "pro-feature", "professional", false, false);
    assert_eq!(decision, "Deny", "empty tier must be denied professional features");

    // Basic features have no principal tier requirement
    let (decision, _) = eval_tier("empty-tier", "", "basic-feature", "basic", false, false);
    assert_eq!(decision, "Allow", "empty tier can still access basic features");
}

// ===========================================================================
// Tier access matrix: systematic coverage
// ===========================================================================

#[test]
fn test_tier_access_matrix() {
    // Complete 3x3 matrix: user_tier x feature_tier -> expected decision.
    // This is the test a senior eng lead checks to confirm the tier model
    // matches the business requirements.
    let matrix = [
        // (user_tier, feature_tier, expected_decision)
        ("enterprise",   "enterprise",   "Allow"),
        ("enterprise",   "professional", "Allow"),
        ("enterprise",   "basic",        "Allow"),
        ("professional", "enterprise",   "Deny"),
        ("professional", "professional", "Allow"),
        ("professional", "basic",        "Allow"),
        ("basic",        "enterprise",   "Deny"),
        ("basic",        "professional", "Deny"),
        ("basic",        "basic",        "Allow"),
    ];

    for (user_tier, feature_tier, expected) in &matrix {
        let (decision, _) = eval_tier(
            &format!("{user_tier}-matrix"),
            user_tier,
            &format!("{feature_tier}-feature"),
            feature_tier,
            false,
            false,
        );
        assert_eq!(
            &decision, expected,
            "tier matrix: {user_tier} user + {feature_tier} feature = expected {expected}, got {decision}"
        );
    }
}
