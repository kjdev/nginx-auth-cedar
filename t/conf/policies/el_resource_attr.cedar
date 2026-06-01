// attribute access on the resource entity literal. The resource id is
// the request URI, so `Resource::"/test.html"` is the request resource
// and its injected attributes resolve.
permit (
    principal,
    action,
    resource
) when {
    Resource::"/test.html".tenant == "acme"
};
