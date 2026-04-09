// `!` logical negation.
permit (
    principal,
    action,
    resource
) when {
    !(principal.role == "guest")
};
