// basic forbid: deny all DELETE requests, permit GET
permit (
    principal,
    action == Action::"GET",
    resource
);

forbid (
    principal,
    action == Action::"DELETE",
    resource
);
