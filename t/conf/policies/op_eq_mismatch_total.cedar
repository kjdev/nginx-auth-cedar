// `==` is total over type mismatch: comparing values of different
// types yields false rather than an evaluation error.
permit (
    principal,
    action,
    resource
) when {
    (1 == "x") == false
    && (true == 1) == false
    && ({a: 1} == duration("0ms")) == false
    && !((1 == "x"))
};
