// Organization-scoped data isolation
// Users can read and write ApiResources owned by their own organization.
// This enforces multi-tenant data isolation: cross-org access is denied by default.
@id("org-scoped-read-write")
permit (
    principal is ApiGateway::User,
    action in [ApiGateway::Action::"read", ApiGateway::Action::"write"],
    resource is ApiGateway::ApiResource
)
when {
    principal.org == resource.owner_org
};
