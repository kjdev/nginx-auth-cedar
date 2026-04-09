// `like` with escaped literal `*` (\*) — matches the literal character only.
permit (
    principal,
    action,
    resource
) when {
    principal.role like "ad\*min"
};
