// Long arithmetic overflow surfaces as an evaluation error: i64::MAX + 1.
// The error makes this `permit` ineligible, so the request is denied.
permit (
    principal,
    action,
    resource
) when {
    9223372036854775807 + 1 > 0
};
