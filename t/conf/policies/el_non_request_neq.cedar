// attribute access on a non-request entity literal errors even under
// `!=`, so the negated form still falls through to default deny.
permit (
    principal,
    action,
    resource
) when {
    Other::"x".role != "admin"
};
