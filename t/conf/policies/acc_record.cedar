// Record literal `{key: expr}` and member access.
permit (
    principal,
    action,
    resource
) when {
    {role: "admin", tenant: "acme"}.role == "admin"
};
