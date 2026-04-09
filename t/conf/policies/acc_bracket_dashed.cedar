// Bracket access for keys that are not valid identifiers.
// The user-defined directive specifies `x-real-ip` as the attribute name.
permit (
    principal,
    action,
    resource
) when {
    context["x-real-ip"] == "10.0.0.1"
};
