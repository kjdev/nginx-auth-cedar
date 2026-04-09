// String + Long is a type mismatch; the evaluator returns an error and
// this `permit` cannot match. With no other permit, the decision is deny.
permit (
    principal,
    action,
    resource
) when {
    principal.role + 1 == 5
};
