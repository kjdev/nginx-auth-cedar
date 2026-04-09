// ipaddr `.isLoopback()` on a CIDR fully inside 127.0.0.0/8.
permit (
    principal,
    action,
    resource
) when {
    ip("127.0.0.1").isLoopback()
};
