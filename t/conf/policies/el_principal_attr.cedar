// attribute access on a request entity literal: `User::"alice"` is the
// principal, so its injected attributes resolve.
permit (
    principal,
    action,
    resource
) when {
    User::"alice".role == "admin"
};
