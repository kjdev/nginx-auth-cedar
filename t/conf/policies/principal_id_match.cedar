// Allow only when the principal id matches "alice".
permit (
    principal == User::"alice",
    action,
    resource
);
