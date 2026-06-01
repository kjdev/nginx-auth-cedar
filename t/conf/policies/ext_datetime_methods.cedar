// datetime methods: offset / durationSince / toDate / toTime.
permit (
    principal,
    action,
    resource
) when {
    datetime("2024-10-15").offset(duration("1d")) == datetime("2024-10-16")
    && datetime("2024-10-15T01:00:00Z").durationSince(datetime("2024-10-15"))
        == duration("1h")
    && datetime("2024-10-15T11:35:00Z").toDate() == datetime("2024-10-15")
    && datetime("2025-02-20T10:35:00Z").toTime() == duration("10h35m")
};
