// duration construction: unit equivalence, multi-unit parsing, and
// signed ordering.
permit (
    principal,
    action,
    resource
) when {
    duration("1h") == duration("60m")
    && duration("1d2h3m4s5ms").toMilliseconds() == 93784005
    && duration("-1d") < duration("1s")
    && duration("-10h") < duration("0s")
};
