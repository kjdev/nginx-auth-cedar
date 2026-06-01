// `has` on a request entity literal reports a present attribute.
permit (
    principal,
    action,
    resource
) when {
    User::"alice" has role
};
