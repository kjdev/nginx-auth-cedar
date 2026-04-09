// String escape `\xHH` - 0x41 = 'A'.
permit (
    principal,
    action,
    resource
) when {
    principal.role == "\x41dmin"
};
