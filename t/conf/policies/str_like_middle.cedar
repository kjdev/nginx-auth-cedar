// `like` with embedded wildcard.
permit (
    principal,
    action,
    resource
) when {
    principal.role like "a*c"
};
