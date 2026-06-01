// `has` on an attribute that was never injected is false, so the
// request falls through to default deny.
permit (
    principal,
    action,
    resource
) when {
    User::"alice" has missing
};
