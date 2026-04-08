// Admins can view and edit any resource
@id("admin-full-access")
permit (
    principal in ApiGateway::Role::"admin",
    action in [ApiGateway::Action::"read", ApiGateway::Action::"write", ApiGateway::Action::"delete"],
    resource
);

// Viewers can only view resources
@id("viewer-read-only")
permit (
    principal in ApiGateway::Role::"viewer",
    action == ApiGateway::Action::"read",
    resource
);

// Direct user permit for testing: alice can always view
@id("alice-view")
permit (
    principal == ApiGateway::User::"alice",
    action == ApiGateway::Action::"read",
    resource
);
