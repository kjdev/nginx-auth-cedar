// Arithmetic operators on Long: +, -, *, unary -.
// Each sub-expression evaluates to a value that, combined, satisfies the
// permit predicate iff every operator is implemented correctly.
permit (
    principal,
    action,
    resource
) when {
    1 + 2 == 3
    && 5 - 2 == 3
    && 2 * 3 == 6
    && -5 + 5 == 0
};
