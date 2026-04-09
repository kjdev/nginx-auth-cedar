// action set: permit GET and POST
permit (
    principal,
    action in [Action::"GET", Action::"POST"],
    resource
);
