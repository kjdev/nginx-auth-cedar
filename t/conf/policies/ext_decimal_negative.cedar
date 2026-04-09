// Negative decimal values: "-0.0001" stored as scaled -1.
permit (
    principal,
    action,
    resource
) when {
    decimal("-0.5").lessThan(decimal("0.0"))
    && decimal("0.0").greaterThan(decimal("-0.0001"))
};
