// Allow only alice with the admin role.
permit (
    principal == User::"alice",
    action,
    resource
) when {
    principal.role == "admin"
};
