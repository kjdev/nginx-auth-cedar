// a record literal with more fields than the context is not equal, so
// the request falls through to default deny.
permit (
    principal,
    action,
    resource
) when {
    context == {ip: "127.0.0.1", extra: "y"}
};
