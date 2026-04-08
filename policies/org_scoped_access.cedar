// Organization-scoped data isolation
// Users can read and write ApiResources owned by their own organization.
// This enforces multi-tenant data isolation: cross-org access is denied by default.
//
// Guard: principal.org must be a real org value (not empty or sentinel).
// Without this, users with missing org claims would match resources with
// equally-missing owner_org via empty-string equality. The entity builder
// uses "__unset__" for missing orgs as a defense-in-depth measure, but this
// policy guard prevents the bypass even with hand-built entities.
@id("org-scoped-read-write")
permit (
    principal is ApiGateway::User,
    action in [ApiGateway::Action::"read", ApiGateway::Action::"write"],
    resource is ApiGateway::ApiResource
)
when {
    principal.org != "" &&
    principal.org != "__unset__" &&
    principal.org == resource.owner_org
};
