// `!=` operator on String: permit when role is not "guest"
permit (
    principal,
    action,
    resource
) when {
    principal.role != "guest"
};
