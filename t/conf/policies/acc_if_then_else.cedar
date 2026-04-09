// `if-then-else` — only the selected branch is evaluated.
permit (
    principal,
    action,
    resource
) when {
    if principal.role == "admin" then true else principal.role == "manager"
};
