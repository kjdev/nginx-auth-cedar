// Accessing a non-existent attribute without a `has` guard is an
// evaluation error. The `permit` cannot match, so the request is denied.
permit (
    principal,
    action,
    resource
) when {
    principal.nonexistent_attr == "x"
};
