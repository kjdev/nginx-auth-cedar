// out-of-order units are an invalid duration; the constructor errors,
// so the `when` never holds and the request falls through to default
// deny.
permit (
    principal,
    action,
    resource
) when {
    duration("1h1d") == duration("1h1d")
};
