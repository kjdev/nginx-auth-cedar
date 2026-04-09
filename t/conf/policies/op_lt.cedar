// `<` operator on Long literals; predicate is always true, so any request
// matches `permit`.
permit (
    principal,
    action,
    resource
) when {
    1 < 2
};
