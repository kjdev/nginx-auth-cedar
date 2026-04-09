// Set methods: `.contains` / `.containsAll` / `.containsAny`.
permit (
    principal,
    action,
    resource
) when {
    ["admin", "manager", "user"].contains(principal.role)
    && ["admin", "manager"].containsAll(["admin"])
    && ["admin", "manager"].containsAny(["admin", "guest"])
};
