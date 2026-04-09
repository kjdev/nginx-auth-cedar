// `has` operator: only proceed to `.role` if it exists.
permit (
    principal,
    action,
    resource
) when {
    principal has role && principal.role == "admin"
};
