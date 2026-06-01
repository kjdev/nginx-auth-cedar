// the bare `context` keyword materializes as a whole record value and
// compares equal to itself.
permit (
    principal,
    action,
    resource
) when {
    context == context
};
