// `>=` exercises both `>` and `==` paths in the comparator.
permit (
    principal,
    action,
    resource
) when {
    2 >= 2 && 3 >= 2
};
