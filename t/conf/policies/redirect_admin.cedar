// Allow when the principal has the admin role, deny otherwise.
permit (
    principal,
    action,
    resource
) when {
    principal.role == "admin"
};

forbid (
    principal,
    action,
    resource
) unless {
    principal.role == "admin"
};
