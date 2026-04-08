// Admins can view and edit any resource
@id("admin-full-access")
permit (
    principal in Role::"admin",
    action in [Action::"ViewResource", Action::"EditResource"],
    resource
);

// Viewers can only view resources
@id("viewer-read-only")
permit (
    principal in Role::"viewer",
    action == Action::"ViewResource",
    resource
);

// Direct user permit for testing: alice can always view
@id("alice-view")
permit (
    principal == User::"alice",
    action == Action::"ViewResource",
    resource
);
