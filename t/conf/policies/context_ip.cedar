// permit only when context.ip matches loopback
permit (
    principal,
    action,
    resource
) when {
    context.ip == "127.0.0.1"
};
