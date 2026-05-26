# nginx-auth-cedar

[![test](https://github.com/kjdev/nginx-auth-cedar/actions/workflows/test.yaml/badge.svg)](https://github.com/kjdev/nginx-auth-cedar/actions/workflows/test.yaml)

Policy-based authorization (AuthZ) for nginx, written as a dynamic module in C.

`nginx-auth-cedar` evaluates a subset of the
[Cedar policy language](https://www.cedarpolicy.com/) against each HTTP
request and returns **allow** or **deny** before the request reaches the
content phase. Policies are loaded once at configuration time, parsed into
an AST on the nginx configuration pool, and evaluated in-process — no
external decision service, no subrequest, no Rust runtime.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/api.cedar;

    server {
        listen 80;

        auth_cedar_principal_attr role     $jwt_claim_role;
        auth_cedar_principal_attr tenant   $jwt_claim_tenant;
        auth_cedar_resource_type           "Endpoint";

        location /api/ {
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
permit (
    principal in Role::"editor",
    action in [Action::"GET", Action::"PUT"],
    resource
) when {
    resource.tenant == principal.tenant
};
```

## Why a nginx module?

| | OPA + Envoy | OPA + nginx (`auth_request`) | AWS Verified Permissions | **nginx-auth-cedar** |
| --- | --- | --- | --- | --- |
| External process | OPA daemon | OPA daemon | Cloud service | **None** |
| Network hop | Yes | Yes (loopback) | Yes (AWS API) | **None** |
| Policy language | Rego | Rego | Cedar | **Cedar (subset)** |
| Variable interop with nginx auth | Manual | Manual | None | **Native** |
| Deployment | Replace data plane | Run OPA alongside | AWS-only | **Drop in a `.so`** |

The existing nginx ecosystem covers authentication (`auth_jwt`,
`auth_oauth2_token`, OpenID Connect) well, but authorization is limited to
`auth_request` (delegate to an external HTTP service) or `allow`/`deny`
(IP-based). `nginx-auth-cedar` adds attribute-based authorization in the
nginx worker itself, consuming the variables that authentication modules
already publish (`$jwt_claim_*`, `$oauth2_*`, etc.).

## Features

- **Cedar policy language subset.** Phases 1 – 4 of the upstream Cedar
  grammar are implemented: `permit` / `forbid` policies, `when` / `unless`,
  scope constraints, `in` hierarchy, `like` patterns, `if … then … else …`,
  set methods, `ip()` / `decimal()` extension types, `is` type checks,
  arithmetic on `Long`, annotations (`@id`, `@advice`), bracket attribute
  access. The full matrix is in
  [`nxe-cedar` features](https://github.com/kjdev/nxe-cedar/blob/main/docs/FEATURES.md).
- **forbid-priority evaluation.** Standard Cedar semantics: any matching
  `forbid` denies; otherwise any matching `permit` allows; default deny.
- **Native nginx variable integration.** Any nginx variable —
  including those set by `ngx_http_auth_jwt_module`, `auth_request`,
  the `realip` module, `map` directives, or Lua — can be mapped onto
  Cedar entity attributes via `auth_cedar_principal_attr`,
  `auth_cedar_resource_attr`, and `auth_cedar_context_attr`.
- **Validated against upstream Cedar.** The Cedar evaluator
  (`nxe-cedar`) is exercised by a Rust FFI oracle that runs the same
  inputs through the official `cedar-policy` crate and compares
  decisions per Phase.
- **Zero runtime dependencies.** nginx core only. No libcurl, no
  jansson, no Rust runtime in the shipped `.so`. Every allocation goes
  through `ngx_pool_t`, so policy ASTs share the configuration
  lifetime and per-request state shares the request lifetime.
- **PRECONTENT phase.** The handler runs after `access` and before
  `content`, so authorization sees the final URI after rewrites but
  cannot be bypassed by handlers that short-circuit earlier phases.

## Quick start

### Build

`nginx-auth-cedar` is a standard `--add-dynamic-module` build. Match the
nginx source tree to the version of nginx the module will be loaded into
(check with `nginx -v`).

```sh
# 1. Fetch the source.
git clone --recurse-submodules https://github.com/kjdev/nginx-auth-cedar.git

# 2. Download the matching nginx source.
NGINX_VERSION=$(nginx -v 2>&1 | sed 's/^[^0-9]*//')
curl -sfL -O https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar -xf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}

# 3. Configure with the same flags as the installed nginx, plus the module.
./configure $(nginx -V 2>&1 | tail -1 | sed 's/^configure arguments: //') \
    --add-dynamic-module=../nginx-auth-cedar

# 4. Build only the dynamic modules.
make modules
```

The result is `objs/ngx_http_auth_cedar_module.so`. Copy it to the nginx
modules directory (typically `/usr/lib/nginx/modules/` or
`/etc/nginx/modules/`) and load it with `load_module` — see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

Requirements:

- A C compiler (GCC or Clang)
- nginx source matching the target nginx version

A container build is also provided:

```sh
docker build --target module -t nginx-auth-cedar .
```

The resulting image is `nginx:alpine` with the module pre-installed and
the `load_module` directive already wired into `/etc/nginx/nginx.conf`.

### Minimal configuration

`/etc/nginx/policies/policy.cedar`:

```cedar
// Allow only the "admin" role.
permit (
    principal,
    action,
    resource
) when {
    principal.role == "admin"
};
```

`/etc/nginx/nginx.conf`:

```nginx
load_module modules/ngx_http_auth_cedar_module.so;

http {
    auth_cedar_policy_file /etc/nginx/policies/policy.cedar;

    server {
        listen 80;

        # Map an nginx variable to a Cedar principal attribute.
        # $jwt_claim_role is published by ngx_http_auth_jwt_module.
        auth_cedar_principal_attr role $jwt_claim_role;

        location /private/ {
            auth_jwt   "private";
            auth_cedar on;

            proxy_pass http://backend;
        }
    }
}
```

A request without `role == "admin"` returns `403 Forbidden`. See
[docs/EXAMPLES.md](docs/EXAMPLES.md) for richer patterns (multi-tenancy,
IP allow-lists, `auth_request` integration).

## How a request is evaluated

```
Client ──→ nginx
            ├─ access phase ........ auth_jwt / auth_oauth2_token / auth_request
            │                        (publish $jwt_claim_*, $oauth2_*, …)
            ├─ precontent phase .... auth_cedar
            │     ├─ build eval context from nginx variables
            │     ├─ run Cedar policy set (forbid-priority)
            │     └─ ALLOW → continue; DENY → return auth_cedar_deny_status
            └─ content phase ....... proxy_pass / fastcgi_pass / …
```

The Cedar evaluation context is built from the request as follows
(defaults; every mapping is configurable):

| Cedar field | nginx source |
| --- | --- |
| `principal` (entity) | `User::"$remote_user"` |
| `principal.<attr>` | `auth_cedar_principal_attr <attr> <var>` |
| `action` (entity) | `Action::"$request_method"` (e.g. `Action::"GET"`) |
| `resource` (entity) | `<resource_type>::"$uri"` |
| `resource.<attr>` | `auth_cedar_resource_attr <attr> <var>` |
| `context.ip` | `$remote_addr` (auto-injected unless overridden) |
| `context.<attr>` | `auth_cedar_context_attr <attr> <var>` |

`auth_cedar_resource_type` (default `Resource`) controls the type of
the `resource` entity, so policies can use
`resource is Endpoint` / `resource is Article` to target the right
location.

## Directives at a glance

```nginx
# main { }
auth_cedar_policy_file <path>;            # load policy file (multiple allowed)

# server { } / location { }
auth_cedar               on | off;        # enable for this location
auth_cedar_principal_attr <name> <var>;   # principal attribute mapping
auth_cedar_resource_type  <type>;         # resource entity type
auth_cedar_resource_attr  <name> <var>;   # resource attribute mapping
auth_cedar_context_attr   <name> <var>;   # context attribute mapping
auth_cedar_deny_status    <code>;         # status code on deny (default 403)
```

The module also publishes the following variables for logging and
downstream decisions:

| Variable | Value |
| --- | --- |
| `$cedar_result` | `allow` or `deny` |
| `$cedar_decision` | `1` (allow) or `0` (deny) |
| `$cedar_policy_id` | `@id` annotation of the matched policy |
| `$cedar_advice` | `@advice` annotation of the matched policy |

Full directive reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Documentation

- [Configuration reference](docs/CONFIGURATION.md) — directives and
  variables, request-to-Cedar mapping, multi-file policies
- [Cedar policy language subset](docs/POLICY_LANGUAGE.md) — supported
  syntax, evaluation model, out-of-scope features
- [Examples](docs/EXAMPLES.md) — RBAC, multi-tenant boundaries, IP
  allow-lists, JWT / OAuth2 / `auth_request` integration
- [Changelog](CHANGELOG.md)

## Scope

`nginx-auth-cedar` is an **authorization** (AuthZ) module. It does **not**
authenticate the request. Combine it with:

- [`ngx_http_auth_jwt_module`](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html)
  for JWT signature verification (or any alternative such as
  [`nginx-auth-jwt`](https://github.com/kjdev/nginx-auth-jwt))
- `auth_request` for Token Introspection / external authentication
- `realip` for trusting `X-Forwarded-For` from upstream proxies

The policy evaluator (`nxe-cedar`) is shipped as a git submodule and may
be reused independently by other nginx modules. See
[`kjdev/nxe-cedar`](https://github.com/kjdev/nxe-cedar).

## License

MIT. See [LICENSE](LICENSE).
