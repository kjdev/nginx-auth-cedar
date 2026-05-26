# Examples

End-to-end examples for `ngx_http_auth_cedar_module`. Each section
includes both the nginx configuration and the corresponding Cedar
policy. The directive reference lives in
[CONFIGURATION.md](CONFIGURATION.md); the policy language is described
in [POLICY_LANGUAGE.md](POLICY_LANGUAGE.md).

## Role-based access control with `auth_jwt`

The `ngx_http_auth_jwt_module` verifies the JWT and publishes claims
as `$jwt_claim_<name>` variables. `auth_cedar` maps the relevant
claims onto the Cedar `principal` and runs the policy.

```nginx
load_module modules/ngx_http_auth_cedar_module.so;
load_module modules/ngx_http_auth_jwt_module.so;

http {
    auth_cedar_policy_file /etc/nginx/policies/rbac.cedar;

    server {
        listen 80;

        auth_jwt          "rbac" token=$http_authorization;
        auth_jwt_key_file /etc/nginx/keys/jwks.json;

        auth_cedar_principal_attr role   $jwt_claim_role;
        auth_cedar_principal_attr tenant $jwt_claim_tenant;

        location /api/ {
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/rbac.cedar

// Editors can read and write articles in their own tenant.
permit (
    principal in Role::"editor",
    action in [Action::"GET", Action::"PUT", Action::"POST"],
    resource
) when {
    resource.tenant == principal.tenant
};

// Viewers can only read.
permit (
    principal in Role::"viewer",
    action == Action::"GET",
    resource
) when {
    resource.tenant == principal.tenant
};
```

Cedar does not resolve the `in Role::"editor"` ancestor automatically;
either populate the role membership through a separate ancestor
injection path (not exposed by this module today — see the "Limitations"
section below) or write the policy as `principal.role == "editor"`.

```cedar
// Same intent without entity hierarchies — works out of the box.
permit (
    principal,
    action in [Action::"GET", Action::"PUT", Action::"POST"],
    resource
) when {
    principal.role == "editor" &&
    resource.tenant == principal.tenant
};
```

## Multi-tenant boundary enforcement

Forbid any cross-tenant access regardless of role. This pattern is
commonly stacked on top of role-based permits: the `forbid`-priority
rule guarantees the tenant boundary cannot be widened by a misconfigured
permit.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/tenant_boundary.cedar;

    server {
        auth_cedar_principal_attr tenant   $jwt_claim_tenant;
        auth_cedar_resource_attr  tenant   $arg_tenant;

        location /api/ {
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/tenant_boundary.cedar

@id("tenant-boundary")
@advice("cross-tenant access denied")
forbid (
    principal,
    action,
    resource
) unless {
    resource.tenant == principal.tenant
};
```

A logged-in user from tenant `acme` requesting
`GET /api/articles?tenant=globex` is denied with `403` regardless of
what other `permit` policies say, and `$cedar_policy_id` carries
`tenant-boundary` for audit.

## IP allow-list with `realip`

Restrict an endpoint to an internal CIDR range. The
[`realip`](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
module rewrites `$remote_addr` to the trusted client IP from an upstream
proxy header; `nginx-auth-cedar` then sees the right address in
`context.ip`.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/ip_allowlist.cedar;

    server {
        # Trust X-Forwarded-For from the upstream load balancer.
        set_real_ip_from 10.0.0.0/8;
        real_ip_header   X-Forwarded-For;

        location /internal/ {
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/ip_allowlist.cedar

permit (
    principal,
    action,
    resource
) when {
    ip("10.0.0.0/8").contains(context.ip) ||
    ip("192.168.0.0/16").contains(context.ip)
};
```

`context.ip` is auto-injected from `$remote_addr`. If `realip` is not
used and the upstream proxy passes the client IP in a header, override
with `auth_cedar_context_attr ip $http_x_forwarded_for;` (but only if
the header is already validated — trusting an unvalidated header is a
spoofing risk).

## Method-aware permission separation

Distinguish read and write paths from a single policy file, using the
fact that `action` is set from `$request_method`.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/method_aware.cedar;

    server {
        auth_cedar_principal_attr role $jwt_claim_role;

        location /api/articles/ {
            auth_cedar_resource_type Article;
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/method_aware.cedar

// Reads are open to anyone with a verified account.
permit (
    principal,
    action in [Action::"GET", Action::"HEAD"],
    resource is Article
);

// Writes require the editor role.
permit (
    principal,
    action in [Action::"POST", Action::"PUT", Action::"PATCH", Action::"DELETE"],
    resource is Article
) when {
    principal.role == "editor" ||
    principal.role == "admin"
};
```

## Resource type discrimination

Share a single policy file across multiple locations, using
`auth_cedar_resource_type` to scope each policy to the right resource.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/shared.cedar;

    server {
        auth_cedar_principal_attr role $jwt_claim_role;

        location /api/articles/ {
            auth_cedar_resource_type Article;
            auth_cedar on;
            proxy_pass http://backend;
        }

        location /admin/ {
            auth_cedar_resource_type AdminPanel;
            auth_cedar on;
            auth_cedar_deny_status 404;   # hide existence
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/shared.cedar

permit (
    principal,
    action,
    resource is Article
);

permit (
    principal,
    action,
    resource is AdminPanel
) when {
    principal.role == "admin"
};
```

## Token Introspection via `auth_request`

When the upstream identity is held by an opaque token (or the JWT
verification lives in an upstream service), `auth_request` performs
the introspection and `auth_request_set` exposes the resulting claims
as nginx variables.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/api.cedar;

    upstream introspect {
        server 127.0.0.1:8000;
    }

    server {
        location = /_introspect {
            internal;
            proxy_method      POST;
            proxy_set_header  Authorization $http_authorization;
            proxy_pass        http://introspect/oauth2/introspect;
        }

        location /api/ {
            auth_request     /_introspect;
            auth_request_set $token_active $upstream_http_x_token_active;
            auth_request_set $token_scope  $upstream_http_x_token_scope;
            auth_request_set $token_sub    $upstream_http_x_token_sub;

            # Make those values visible to Cedar.
            auth_cedar_principal_attr active $token_active;
            auth_cedar_principal_attr scope  $token_scope;
            auth_cedar_principal_attr sub    $token_sub;

            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/api.cedar

forbid (
    principal,
    action,
    resource
) unless {
    principal.active == "true"
};

permit (
    principal,
    action == Action::"GET",
    resource
) when {
    principal.scope like "*read*"
};
```

The introspection endpoint is expected to set response headers like
`X-Token-Active`, `X-Token-Scope`, `X-Token-Sub` — adjust to match the
actual service.

## Time-of-day restriction

Restrict writes to business hours. Since `nxe-cedar` does not implement
the `datetime` type, pre-compute the hour-of-day with a `map` directive
and inject it through `context`.

```nginx
http {
    auth_cedar_policy_file /etc/nginx/policies/hours.cedar;

    # Extract the hour from $time_iso8601 (HH part).
    map $time_iso8601 $hour_of_day {
        ~^.{11}(\d{2}) $1;
        default        0;
    }

    server {
        auth_cedar_principal_attr role $jwt_claim_role;
        auth_cedar_context_attr   hour $hour_of_day;

        location /api/ {
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/hours.cedar

forbid (
    principal,
    action in [Action::"POST", Action::"PUT", Action::"DELETE"],
    resource
) when {
    context.hour < 9 || context.hour >= 18
} unless {
    principal.role == "admin"   // admins bypass the time window
};
```

`context.hour` is injected as a string. Cedar string comparison would
not work for ordering, so the policy relies on numeric comparison;
`nxe-cedar` accepts string-to-long coercion at attribute injection
time so `context.hour < 9` works as long as the value is a decimal
string.

## Auditing via access log

Capture the Cedar decision and the matched policy in the access log so
denials can be analyzed without parsing the error log.

```nginx
log_format auth '$remote_addr - $remote_user [$time_local] '
                '"$request" $status $body_bytes_sent '
                'cedar=$cedar_result policy="$cedar_policy_id" '
                'advice="$cedar_advice"';

http {
    auth_cedar_policy_file /etc/nginx/policies/audit.cedar;

    server {
        access_log /var/log/nginx/auth.log auth;

        location /api/ {
            auth_cedar on;
            proxy_pass http://backend;
        }
    }
}
```

```cedar
// /etc/nginx/policies/audit.cedar

@id("admin-only")
@advice("admin role required")
permit (
    principal,
    action,
    resource
) when {
    principal.role == "admin"
};
```

A denied request shows up as:

```
192.0.2.10 - alice [26/May/2026:10:00:00 +0900] "GET /api/articles" 403 0 cedar=deny policy="" advice=""
```

When a `permit` matches and the request is allowed:

```
192.0.2.10 - alice [26/May/2026:10:01:00 +0900] "GET /api/articles" 200 1234 cedar=allow policy="admin-only" advice="admin role required"
```

## Limitations to keep in mind

- **No ancestor injection from nginx config.** The Cedar `in`
  operator with custom hierarchies (e.g. `principal in Role::"editor"`)
  relies on the caller injecting ancestor lists. `nginx-auth-cedar`
  does not expose a directive for that today — model role membership
  through a principal attribute (`principal.role == "editor"`)
  instead.
- **No JWT verification.** Combine with `auth_jwt` or `auth_request`
  for signature, expiry, and audience checks.
- **No `datetime` type.** Pre-compute integer values
  (hour-of-day, day-of-week, …) and pass via `context`.
- **`auth_cedar_*_attr` does not cumulate across server / location.**
  Defining a single mapping in a `location` discards all the parent
  mappings — repeat them if both sets are needed.
