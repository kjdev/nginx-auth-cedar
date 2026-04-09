// `.isEmpty()` on Set literal.
permit (
    principal,
    action,
    resource
) when {
    [].isEmpty() && !["x"].isEmpty()
};
