// forbid overrides permit
permit (
    principal,
    action,
    resource
);

forbid (
    principal,
    action == Action::"DELETE",
    resource
);
