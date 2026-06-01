// a bare trailing 'T' without a time component is an invalid datetime;
// the constructor errors, so the `when` never holds and the request
// falls through to default deny.
permit (
    principal,
    action,
    resource
) when {
    datetime("2024-08-21T") == datetime("2024-08-21T00:00:00.000Z")
};
