// `is` type-check operator at expression level.
// The module always sets principal type to "User".
permit (
    principal,
    action,
    resource
) when {
    principal is User
};
