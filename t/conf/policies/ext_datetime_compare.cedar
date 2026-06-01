// datetime construction, normalization, and ordering.
// date-only normalizes to UTC midnight; numeric offsets normalize to
// UTC; millisecond precision is preserved and ordered.
permit (
    principal,
    action,
    resource
) when {
    datetime("2024-10-15") == datetime("2024-10-15T00:00:00.000Z")
    && datetime("2024-10-15T11:35:00+0100") == datetime("2024-10-15T10:35:00Z")
    && datetime("2024-10-15") < datetime("2024-10-16")
    && datetime("2024-10-15T11:35:00.123Z") > datetime("2024-10-15T11:35:00.000Z")
};
