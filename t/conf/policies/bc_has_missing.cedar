// `has` on a field that was never injected is false, so the request
// falls through to default deny.
permit (
    principal,
    action,
    resource
) when {
    context has missing
};
