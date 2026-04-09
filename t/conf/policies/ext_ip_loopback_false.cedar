// ipaddr `.isLoopback()` on a non-loopback address evaluates to false.
permit (
    principal,
    action,
    resource
) when {
    ip("8.8.8.8").isLoopback()
};
