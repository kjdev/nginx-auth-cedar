// Per Cedar's forbid-priority semantics, an evaluation error in a forbid
// makes that forbid ineligible (not deny-on-error). The permit then
// determines the decision.
permit (
    principal,
    action,
    resource
);

forbid (
    principal,
    action,
    resource
) when {
    principal.role + 1 == 5
};
