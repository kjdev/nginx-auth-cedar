# Configuration reference

This document is the directive and variable reference for
`ngx_http_auth_cedar_module`. See [POLICY_LANGUAGE.md](POLICY_LANGUAGE.md)
for the Cedar policy language subset and [EXAMPLES.md](EXAMPLES.md) for
end-to-end scenarios.

## Loading the module

The module is dynamic; load it from the main `nginx.conf` before any
`http { }` block:

```nginx
load_module modules/ngx_http_auth_cedar_module.so;
```

For container images built via the bundled `Dockerfile`, the `load_module`
line is injected into `/etc/nginx/nginx.conf` automatically.

## Directives

| Directive | Description |
| --- | --- |
| [auth_cedar](#auth_cedar) | Enable or disable Cedar enforcement for the location |
| [auth_cedar_policy_file](#auth_cedar_policy_file) | Load a Cedar policy file at configuration time |
| [auth_cedar_principal_id](#auth_cedar_principal_id) | Override the identifier used for the `principal` entity |
| [auth_cedar_principal_attr](#auth_cedar_principal_attr) | Map an nginx variable to a Cedar `principal` attribute |
| [auth_cedar_resource_type](#auth_cedar_resource_type) | Set the entity type used for the `resource` |
| [auth_cedar_resource_attr](#auth_cedar_resource_attr) | Map an nginx variable to a Cedar `resource` attribute |
| [auth_cedar_context_attr](#auth_cedar_context_attr) | Map an nginx variable to a Cedar `context` attribute |
| [auth_cedar_deny_status](#auth_cedar_deny_status) | HTTP status returned on deny |

### auth_cedar

```
Syntax:  auth_cedar on | off | id [id ...];
Default: auth_cedar off;
Context: location, if in location
```

Selects which Cedar policy set applies to the location. The argument is
one of:

- `on` — apply the union of **every** policy set declared via
  `auth_cedar_policy_file`.
- `off` — skip the handler entirely.
- `id [id ...]` — apply the union of the policy sets declared under the
  listed ids only. Separate multiple ids with whitespace.

```nginx
location /api {
    auth_cedar api;            # apply the "api" id only
}
location /admin {
    auth_cedar api admin;      # union of "api" and "admin"
}
location /health {
    auth_cedar off;            # skip authorization
}
```

`on` and `off` are reserved words and cannot be used as ids; mixing
`on` / `off` with one or more ids in the same directive is rejected at
configuration time (`emerg`). Repeating the same id within one directive
or referencing an id that was not declared via `auth_cedar_policy_file`
is rejected the same way, aborting `nginx -t` / startup.

Using `auth_cedar on` without any `auth_cedar_policy_file` directive is
also rejected at configuration time.

### auth_cedar_policy_file

```
Syntax:  auth_cedar_policy_file id path [path ...];
Default: -
Context: http
```

Loads one or more Cedar policy files under the given id. Multiple paths
on a single directive are merged into one policy set, which is then
selectable from `auth_cedar` by id.

The id must match `[A-Za-z0-9_-]+`. The empty string, `on`, and `off`
are reserved and rejected.

Declaring the same id with more than one `auth_cedar_policy_file`
directive is rejected at configuration time (`emerg`). To bundle several
files under one id, list them all on a single directive.

Policy ordering follows the order in which the files appear on the
directive. Policy `@id` annotations are **not deduplicated across
files**, so two files declaring the same `@id` will both contribute to
the evaluation.

Relative paths are resolved against the nginx prefix (the same rules as
`access_log` or `include`).

```nginx
http {
    auth_cedar_policy_file api
        /etc/nginx/policies/api_base.cedar
        /etc/nginx/policies/api_tenant.cedar;
    auth_cedar_policy_file admin /etc/nginx/policies/admin.cedar;
}
```

A parse error (invalid syntax, unsupported construct, unreadable file)
aborts `nginx -t` / startup with an `emerg`-level log message. A single
policy file is capped at **16 MiB**; larger files are rejected at
configuration time to keep configuration-pool growth bounded.

### auth_cedar_principal_id

```
Syntax:  auth_cedar_principal_id value;
Default: -
Context: server, location
```

Overrides the identifier of the `principal` entity. The value is a
[complex value](https://nginx.org/en/docs/dev/development_guide.html#http_complex_values),
so a literal string, an nginx variable, or a concatenation can all be
used.

```nginx
# JWT subject claim
auth_cedar_principal_id $jwt_claim_sub;

# explicit identifier for a static service location
auth_cedar_principal_id "service-account";
```

When not set, the principal id falls back to the user from
`ngx_http_auth_basic_module` (`r->headers_in.user`, which `$remote_user`
also reads). Built-in `$remote_user` is not `NGX_HTTP_VAR_CHANGEABLE`, so
`auth_request_set $remote_user ...` is rejected at configuration time and
does not act as a fallback source. For JWT / OAuth2 deployments without
Basic Auth, set this directive explicitly (e.g.
`auth_cedar_principal_id $jwt_claim_sub;`) to expose a meaningful
identifier (otherwise the principal id will be the empty string and
`principal == User::"..."` policies will never match).

When the directive is set but the complex value resolves to an empty
string (for example, `$jwt_claim_sub` is empty because the request has
no JWT), the explicit value still takes effect: the principal id stays
empty and is **not** silently replaced with `$remote_user`. Policies
matching `principal == User::"..."` will not fire, but an unconditional
`permit (principal, ...);` rule will still allow the request because
Cedar treats `User::""` as a valid principal. If a multi-source
fallback is required, encode it in the complex value itself (e.g.
`map` / `set` directives to choose the first non-empty source).
Empty resolutions are logged at `debug_http` to aid diagnosis.

The principal entity type is always `User`.

### auth_cedar_principal_attr

```
Syntax:  auth_cedar_principal_attr name value;
Default: -
Context: server, location
```

Maps an nginx variable (or any
[complex value](https://nginx.org/en/docs/dev/development_guide.html#http_complex_values)
— literal strings, variable expansions, etc.) to a Cedar `principal`
attribute. The mapping is resolved per request via
`ngx_http_complex_value()`, so anything published by an earlier phase
(`auth_jwt`, `auth_oauth2_token`, `map`, Lua, …) is available.

```nginx
auth_cedar_principal_attr role     $jwt_claim_role;
auth_cedar_principal_attr tenant   $jwt_claim_tenant_id;
auth_cedar_principal_attr verified $jwt_claim_email_verified;
```

The Cedar policy can then read `principal.role`, `principal.tenant`,
`principal.verified`.

Repeating the directive with the same attribute name within a single
scope is rejected at configuration time (mirrors the duplicate-key
rejection in `nxe-cedar`'s attribute injection API). When the variable
resolves to an empty string, the attribute is **not** injected (so
`principal has role` reflects whether the claim was actually present
rather than always being `true`).

The principal entity is always typed as `User`; its id comes from
`auth_cedar_principal_id` when configured and falls back to `$remote_user`
otherwise (see [auth_cedar_principal_id](#auth_cedar_principal_id)).

### auth_cedar_resource_type

```
Syntax:  auth_cedar_resource_type type;
Default: auth_cedar_resource_type Resource;
Context: server, location
```

Sets the entity type used to build the `resource` for this location. The
resource is constructed as `<type>::"<URI>"`, so a policy can target the
right location with `resource is Endpoint` / `resource is Article` even
when a single policy file is shared.

```nginx
location /api/articles/ {
    auth_cedar_resource_type Article;
    auth_cedar on;
}

location /admin/ {
    auth_cedar_resource_type AdminPanel;
    auth_cedar on;
}
```

```cedar
permit (
    principal in Role::"editor",
    action,
    resource is Article
);

forbid (
    principal,
    action,
    resource is AdminPanel
) unless {
    principal.role == "admin"
};
```

### auth_cedar_resource_attr

```
Syntax:  auth_cedar_resource_attr name value;
Default: -
Context: server, location
```

Maps an nginx variable to a Cedar `resource` attribute. Identical
semantics to `auth_cedar_principal_attr` but populates `resource.<name>`.

```nginx
auth_cedar_resource_attr tenant $arg_tenant;
auth_cedar_resource_attr method $request_method;
```

### auth_cedar_context_attr

```
Syntax:  auth_cedar_context_attr name value;
Default: -
Context: server, location
```

Maps an nginx variable to a Cedar `context` attribute. Identical
semantics to `auth_cedar_principal_attr` but populates `context.<name>`.

```nginx
auth_cedar_context_attr ua    $http_user_agent;
auth_cedar_context_attr hour  $time_iso8601;
auth_cedar_context_attr ip    $http_x_forwarded_for;   # overrides default
```

`context.ip` is auto-injected from `$remote_addr` by default. Mapping a
custom value to `ip` via `auth_cedar_context_attr` **replaces** the
auto-injection (the duplicate-key rejection in the underlying injection
API would otherwise abort the request). Use this to trust a header
populated by the [`realip`](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
module.

### auth_cedar_deny_status

```
Syntax:  auth_cedar_deny_status code;
Default: auth_cedar_deny_status 403;
Context: server, location
```

HTTP status returned when the policy set denies the request. Useful when
downstream tooling needs to distinguish authorization failures (e.g. `401`
to trigger a re-auth redirect, `404` to hide resource existence).

```nginx
location /admin/ {
    auth_cedar             on;
    auth_cedar_deny_status 404;     # hide existence of admin endpoints
}
```

## Variables

| Variable | Description |
| --- | --- |
| [$cedar_result](#cedar_result) | `allow` or `deny` (human-readable) |
| [$cedar_decision](#cedar_decision) | `1` or `0` (machine-readable) |
| [$cedar_policy_id](#cedar_policy_id) | `@id` annotation of the first matched policy |
| [$cedar_advice](#cedar_advice) | `@advice` annotation of the first matched policy |

All variables are marked `NGX_HTTP_VAR_NOCACHEABLE`, so log subrequests
and downstream `map` lookups always observe the live decision. They are
**unset** on locations where `auth_cedar` did not run (e.g. inside a
sibling `location` where `auth_cedar off;` is in effect).

### $cedar_result

`allow` or `deny`. Human-readable; the natural choice for `log_format`.

```nginx
log_format auth '$remote_addr - $remote_user [$time_local] '
                '"$request" $status $body_bytes_sent '
                'cedar=$cedar_result policy="$cedar_policy_id" '
                'advice="$cedar_advice"';
access_log /var/log/nginx/access.log auth;
```

### $cedar_decision

`1` (allow) or `0` (deny). Machine-readable; useful for `map` / Lua
dispatch where a boolean is more convenient than a string.

### $cedar_policy_id

The `@id` annotation of the first matched policy in **policy-file
declaration order** — i.e. the first `forbid` to fire on deny, or the
first `permit` to fire on allow. When multiple policies match (for
example two `forbid` policies covering the same request), only the
first match's annotation is exposed. Unset when no policy matched
(default-deny path) or when the matched policy carries no `@id`
annotation. Useful for tying a denied request back to the exact policy
that fired.

```cedar
@id("policy-001-admin-only")
forbid (
    principal,
    action,
    resource is AdminPanel
) unless {
    principal.role == "admin"
};
```

### $cedar_advice

The `@advice` annotation of the first matched policy. Same semantics as
`$cedar_policy_id` but with the `@advice` key, intended to carry a
human-readable reason that ends up in logs without the operator needing
to maintain a separate `policy-id → reason` mapping.

```cedar
@id("rate-limit-exempt")
@advice("rate limit is bypassed for service accounts")
permit (
    principal in Role::"service",
    action,
    resource
);
```

## How a request is mapped to Cedar entities

| Cedar field | nginx source | Customization |
| --- | --- | --- |
| `principal` (entity) | `User::"<id>"` — id comes from `auth_cedar_principal_id` if set, otherwise `$remote_user` | Type fixed to `User`. `auth_cedar_principal_id <var>;` to override the id (for JWT / OAuth2 setups that don't populate `$remote_user`). |
| `principal.<attr>` | — | `auth_cedar_principal_attr <attr> <var>;` |
| `action` (entity) | `Action::"$request_method"` (e.g. `Action::"GET"`) | Not configurable; the request method is canonical. |
| `resource` (entity) | `<resource_type>::"$uri"` | `auth_cedar_resource_type <type>;` controls the type. |
| `resource.<attr>` | — | `auth_cedar_resource_attr <attr> <var>;` |
| `context.ip` | `$remote_addr` (auto-injected) | `auth_cedar_context_attr ip <var>;` overrides. |
| `context.<attr>` | — | `auth_cedar_context_attr <attr> <var>;` |

## Configuration inheritance

The module follows nginx's standard server-to-location merge rules:

| Setting | Merge rule | Default |
| --- | --- | --- |
| `auth_cedar` | inherits the parent's mode (`on` / `off` / id list) when the child does not set `auth_cedar`; otherwise the child overrides the parent entirely | `off` |
| `auth_cedar_resource_type` | child overrides parent (string merge) | `Resource` |
| `auth_cedar_principal_id` | child overrides parent | — (falls back to `$remote_user`) |
| `auth_cedar_principal_attr` / `auth_cedar_resource_attr` / `auth_cedar_context_attr` | child overrides parent **entirely** if the child defines any mappings; otherwise inherits the parent list | — |
| `auth_cedar_deny_status` | child overrides parent | `403` |
| `auth_cedar_policy_file` | global (`http` context only); the id namespace is unique across the http block | — |

The "child overrides entirely" behavior for the attribute-mapping
directives is important: declaring a single `auth_cedar_principal_attr`
inside a `location` block discards every principal attribute mapping
inherited from the surrounding `server` block. Repeat the parent
mappings in the child if you need them both.

## Operational notes

### Internal redirects

When nginx internally redirects a request (`error_page = ...`,
`try_files`, named locations, etc.) the destination location's policy
mappings are evaluated afresh. The per-request context caches the
previous decision only for re-entry into the **same** location, so a
request that was permitted at `/foo` and is then redirected to `/bar`
runs the policy set again against `/bar`'s `auth_cedar_principal_attr`,
`auth_cedar_resource_type`, etc. This prevents a permissive decision
from leaking into a stricter location through `error_page`-driven
internal redirects.

### Policy reloads

Policy files are read at configuration time. A change to a policy file
takes effect on `nginx -s reload` (or a full restart). The reload is
performed against the configuration pool, so an invalid policy after a
reload leaves the worker running the previous policy set.

### Logging policy denials

A denial is logged at `info` level with the format:

```
cedar: access denied for "GET /admin/users", principal="alice", client=192.0.2.10
```

The `$cedar_policy_id` and `$cedar_advice` variables expose the matched
policy to `access_log` formats, so an audit trail can be built without
parsing the `error_log`.

### Combining with auth_request

`nginx-auth-cedar` runs in PRECONTENT, after `auth_request` (access
phase). Anything `auth_request` publishes through `auth_request_set`
becomes available as an nginx variable and can therefore be mapped via
`auth_cedar_principal_attr` / `auth_cedar_context_attr`. This is the
recommended path for Token Introspection (RFC 7662) and similar
opaque-token flows where the claim set is computed by an upstream
service.

### Combining with auth_jwt

The
[`ngx_http_auth_jwt_module`](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html)
publishes JWT claims as `$jwt_claim_<name>` variables. These can be fed
directly into `auth_cedar_principal_attr`. `nginx-auth-cedar` does **not**
verify JWT signatures — combine it with `auth_jwt` (or an equivalent) in
the access phase to enforce signature, expiry, and audience.
