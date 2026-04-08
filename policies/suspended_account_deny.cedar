// Deny override for suspended accounts
// Suspended users are denied all actions regardless of any permit policy.
// Uses forbid effect to override permits -- Cedar evaluates forbid policies
// after permits, so this provides a hard deny that cannot be overridden by
// any permit policy in the set.
//
// P0-2 compliance: `suspended` is marked required (not optional with `?`) in
// the schema. Cedar's skip-on-error semantics would skip this forbid if the
// attribute were missing, allowing permit policies to fire -- a security bypass.
@id("suspended-account-deny")
forbid (
    principal is ApiGateway::User,
    action,
    resource
)
when {
    principal.suspended == true
};
