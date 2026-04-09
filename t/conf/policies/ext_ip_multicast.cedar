// ipaddr `.isMulticast()` covers both v4 (224.0.0.0/4) and v6 (ff00::/8).
permit (
    principal,
    action,
    resource
) when {
    ip("224.0.0.1").isMulticast()
    && ip("ff02::1").isMulticast()
    && !ip("10.0.0.1").isMulticast()
};
