// Role-based route access
// Admins can perform all actions on any ApiResource.
@id("rbac-admin-all")
permit (
    principal in ApiGateway::Role::"admin",
    action in [
        ApiGateway::Action::"read",
        ApiGateway::Action::"write",
        ApiGateway::Action::"delete",
        ApiGateway::Action::"list",
        ApiGateway::Action::"admin"
    ],
    resource is ApiGateway::ApiResource
);

// Editors can read, write, and list ApiResources.
@id("rbac-editor-rw")
permit (
    principal in ApiGateway::Role::"editor",
    action in [
        ApiGateway::Action::"read",
        ApiGateway::Action::"write",
        ApiGateway::Action::"list"
    ],
    resource is ApiGateway::ApiResource
);

// Viewers can only read and list ApiResources.
@id("rbac-viewer-read")
permit (
    principal in ApiGateway::Role::"viewer",
    action in [
        ApiGateway::Action::"read",
        ApiGateway::Action::"list"
    ],
    resource is ApiGateway::ApiResource
);
