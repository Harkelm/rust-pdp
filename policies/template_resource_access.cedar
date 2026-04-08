// Template with principal and resource placeholders
// This template allows per-customer instantiation for specific resource grants.
// Instantiate with a concrete principal (e.g., User::"customer-123") and
// a concrete resource (e.g., ApiResource::"customer-123-api") to grant
// read and list access for that specific pairing.
@id("template-resource-access")
permit (
    principal == ?principal,
    action in [ApiGateway::Action::"read", ApiGateway::Action::"list"],
    resource == ?resource
);
