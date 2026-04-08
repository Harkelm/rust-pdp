// Test consumer "alice" (UUID: 00000000-0000-0000-0000-000000000001) can GET and POST on /api/test
@id("allow-alice-read")
permit(
    principal == User::"00000000-0000-0000-0000-000000000001",
    action == Action::"get",
    resource == Resource::"/api/test"
);

@id("allow-alice-write")
permit(
    principal == User::"00000000-0000-0000-0000-000000000001",
    action == Action::"post",
    resource == Resource::"/api/test"
);

// Default deny: bob (UUID: 00000000-0000-0000-0000-000000000002) and all others
// are denied by Cedar's default-deny semantics - no permit = Deny.
