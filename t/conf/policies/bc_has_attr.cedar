// `has` on the bare context record reports a present field.
permit (
    principal,
    action,
    resource
) when {
    context has foo
};
