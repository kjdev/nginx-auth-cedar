// Bracket access `["key"]` - equivalent to dot access for plain idents,
// but the only form available for keys that are not valid identifiers.
permit (
    principal,
    action,
    resource
) when {
    principal["role"] == "admin"
};
