// ipaddr family inspection methods.
permit (
    principal,
    action,
    resource
) when {
    ip("10.0.0.1").isIpv4()
    && !ip("10.0.0.1").isIpv6()
    && ip("::1").isIpv6()
    && !ip("::1").isIpv4()
};
