// when/unless conditions
permit (
    principal,
    action,
    resource
) when {
    principal.role == "admin"
};

// tenant isolation: deny unless same tenant
forbid (
    principal,
    action,
    resource
) unless {
    resource.tenant == principal.tenant
};
