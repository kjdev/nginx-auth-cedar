// a request entity literal and the matching request variable resolve to
// the same attribute value.
permit (
    principal,
    action,
    resource
) when {
    User::"alice".role == principal.role
};
