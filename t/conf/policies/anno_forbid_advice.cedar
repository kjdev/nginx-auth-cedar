// permit all, but forbid DELETE with @id and @advice
permit (
    principal,
    action,
    resource
);

@id("forbid-delete")
@advice("DELETE is not allowed on this resource")
forbid (
    principal,
    action == Action::"DELETE",
    resource
);
