// the bare context record compares equal to a matching record literal.
// The test pins `context.ip` to a known value so the whole-record
// comparison is deterministic.
permit (
    principal,
    action,
    resource
) when {
    context == {ip: "127.0.0.1"}
};
