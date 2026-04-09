// decimal ordering methods: lessThan / lessThanOrEqual / greaterThan /
// greaterThanOrEqual. Each direction is exercised positively and
// negatively in a single `when`.
permit (
    principal,
    action,
    resource
) when {
    decimal("1.5").lessThan(decimal("2.0"))
    && decimal("2.0").lessThanOrEqual(decimal("2.0"))
    && decimal("3.14").greaterThan(decimal("3.0"))
    && decimal("3.0").greaterThanOrEqual(decimal("3.0"))
    && !decimal("2.0").lessThan(decimal("1.5"))
};
