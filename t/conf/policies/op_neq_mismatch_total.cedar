// `!=` is total over type mismatch: comparing values of different
// types yields true rather than an evaluation error.
permit (
    principal,
    action,
    resource
) when {
    1 != "x"
    && true != datetime("2020-01-01")
    && [1] != 1
};
