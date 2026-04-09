// String escape `\u{...}` - U+4E2D = `中` (UTF-8 E4 B8 AD).
permit (
    principal,
    action,
    resource
) when {
    principal.role == "\u{4e2d}"
};
