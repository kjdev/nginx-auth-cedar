// basic permit: allow all GET requests
permit (
    principal,
    action == Action::"GET",
    resource
);
