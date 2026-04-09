// permit POST only (for merge testing with basic_permit.cedar)
permit (
    principal,
    action == Action::"POST",
    resource
);
