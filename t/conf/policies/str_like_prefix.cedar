// `like` with trailing wildcard.
permit (
    principal,
    action,
    resource
) when {
    principal.role like "admin*"
};
