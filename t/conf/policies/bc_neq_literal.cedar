// the bare context record compares against a record literal; a field
// value difference makes them unequal, so `!=` holds.
permit (
    principal,
    action,
    resource
) when {
    context != {a: 99}
};
