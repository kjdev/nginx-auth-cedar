// no permit policies: default deny applies to all requests
forbid (
    principal,
    action == Action::"DELETE",
    resource
);
