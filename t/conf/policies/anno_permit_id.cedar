// permit with @id annotation
@id("permit-all-get")
permit (
    principal,
    action == Action::"GET",
    resource
);
