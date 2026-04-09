// String escape `\t`.
permit (
    principal,
    action,
    resource
) when {
    principal.role == "a\tb"
};
