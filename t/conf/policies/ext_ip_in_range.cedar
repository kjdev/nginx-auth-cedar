// ipaddr `.isInRange(ipaddr)` - receiver CIDR must be at least as specific
// as the argument. `10.0.0.5/32` is within `10.0.0.0/8`.
permit (
    principal,
    action,
    resource
) when {
    ip("10.0.0.5/32").isInRange(ip("10.0.0.0/8"))
    && !ip("8.8.8.8").isInRange(ip("10.0.0.0/8"))
};
