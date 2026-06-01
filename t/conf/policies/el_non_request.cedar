// attribute access on an entity literal that is neither principal,
// action, nor resource cannot resolve; the access errors, the `when`
// never holds, and both `==` and `!=` forms fall through to default
// deny.
permit (
    principal,
    action,
    resource
) when {
    Other::"x".role == "admin"
};
