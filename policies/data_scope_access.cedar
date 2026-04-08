// ABAC data scope control
// Users can read ApiResources only when the resource's classification
// is within the set of data scopes the user is authorized to access.
// The `allowed_scopes` attribute on User is a Set<String> provisioned
// from the JWT/entitlement store; `classification` on ApiResource is a
// static label (e.g., "public", "internal", "confidential", "restricted").
@id("data-scope-read")
permit (
    principal is ApiGateway::User,
    action == ApiGateway::Action::"read",
    resource is ApiGateway::ApiResource
)
when {
    principal.allowed_scopes.contains(resource.classification)
};
