// duration conversions: toMilliseconds / toSeconds / toMinutes /
// toHours / toDays, including truncation toward zero for negatives.
permit (
    principal,
    action,
    resource
) when {
    duration("1d").toMinutes() == 1440
    && duration("1d").toHours() == 24
    && duration("36h").toDays() == 1
    && duration("90s").toSeconds() == 90
    && duration("-1500ms").toSeconds() == -1
};
