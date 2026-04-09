// `<` operator on Long literals; predicate is always false, so no request
// matches `permit` (default deny).
permit (
    principal,
    action,
    resource
) when {
    2 < 1
};
