// Subscription tier feature gating
// Enterprise users can access enterprise-tier features.
@id("tier-enterprise-access")
permit (
    principal is ApiGateway::User,
    action == ApiGateway::Action::"read",
    resource is ApiGateway::Feature
)
when {
    principal.subscription_tier == "enterprise" &&
    resource.required_tier == "enterprise"
};

// Professional and enterprise users can access professional-tier features.
@id("tier-professional-access")
permit (
    principal is ApiGateway::User,
    action == ApiGateway::Action::"read",
    resource is ApiGateway::Feature
)
when {
    (principal.subscription_tier == "enterprise" ||
     principal.subscription_tier == "professional") &&
    resource.required_tier == "professional"
};

// All authenticated users can access basic-tier features.
@id("tier-basic-access")
permit (
    principal is ApiGateway::User,
    action == ApiGateway::Action::"read",
    resource is ApiGateway::Feature
)
when {
    resource.required_tier == "basic"
};
