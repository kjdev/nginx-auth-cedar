// `&&` / `||` short-circuit logical operators.
// Permit if role is admin OR manager, but never if it is guest.
permit (
    principal,
    action,
    resource
) when {
    (principal.role == "admin" || principal.role == "manager")
    && principal.role != "guest"
};
