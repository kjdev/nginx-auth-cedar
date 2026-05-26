# Changelog

## [fb0aea3](../../commit/fb0aea3) - 2026-05-27

### Added

- Initial release of the `ngx_http_auth_cedar_module` dynamic module — a Cedar-based authorization (AuthZ) handler that evaluates a policy set against each request at the PRECONTENT phase
  - The handler runs after the access phase (so it sees the post-rewrite URI and the variables that `auth_jwt` / `auth_oauth2_token` / `auth_request` have already populated) and before the content phase (so policy decisions cannot be bypassed by a content handler that short-circuits earlier); a per-request `ngx_http_auth_cedar_ctx_t` caches the decision and the matching policy details so subsequent re-entries on the same request reuse the result instead of re-evaluating
  - Policy evaluation flows through `nxe_cedar_eval_detail()` so the matched policies are kept on the request pool; the diagnostics are then surfaced through the `$cedar_policy_id` / `$cedar_advice` variables for audit logging without forcing the caller to re-parse the policy text
- Directives for declaring the policy set and shaping the Cedar evaluation context
  - `auth_cedar_policy_file <path>` (http) loads a Cedar policy file at configuration time, parses it onto the configuration pool via `nxe_cedar_parse()`, and merges its policies into a single policy set; the directive may be repeated to compose multiple files (each file is parsed independently and the resulting policies are concatenated into the shared `policy_set`)
  - `auth_cedar on|off` (server / location / `if`) toggles enforcement for the location; merging follows the standard nginx flag semantics, defaulting to off
  - `auth_cedar_principal_attr <name> <value>` / `auth_cedar_resource_attr` / `auth_cedar_context_attr` (server / location, may be repeated) bind a Cedar entity attribute to any nginx variable / complex value; mappings stack up the configuration hierarchy and the evaluator pulls the current value at request time via `ngx_http_complex_value()`, so anything the access phase publishes (`$jwt_claim_*`, `$oauth2_*`, `$arg_*`, `map`, Lua, …) is reachable from policies as `principal.X` / `resource.X` / `context.X`
  - `auth_cedar_resource_type <type>` (server / location, default `Resource`) selects the entity type of the `resource` so policies can use `resource is Article` / `resource is Endpoint` to discriminate locations from a single shared policy file
  - `auth_cedar_deny_status <code>` (server / location, default `403`) overrides the HTTP status returned on deny; useful when downstream tooling distinguishes authorization failures by code (e.g. 401 to trigger a re-auth redirect)
- Entity construction from the nginx request (`ngx_auth_cedar_entity.c`)
  - `principal` is `User::"$remote_user"` (the authenticated user identity, or the empty string when no authentication ran); `action` is `Action::"<HTTP method>"`; `resource` is `<resource_type>::"<URI>"` so URI-prefix policies like `resource.path like "/admin/*"` (where `path` is the user-supplied resource attribute) work without further configuration
  - `context.ip` is auto-injected from `$remote_addr` for convenience (matches the most common policy idiom `ip("10.0.0.0/8").contains(context.ip)`); the auto-injection is skipped when the operator explicitly maps `ip` via `auth_cedar_context_attr` (e.g. to trust `X-Forwarded-For` through the `realip` module), avoiding the duplicate-key rejection that `nxe-cedar` enforces on attribute injection
  - Empty variable values are dropped from the entity rather than injected as an empty string, so `principal has role` reflects the actual presence of the claim instead of always being `true`
- Result-exposing nginx variables (`ngx_auth_cedar_variable.c`), all marked `NGX_HTTP_VAR_NOCACHEABLE` so log subrequests see the live decision
  - `$cedar_result` — `"allow"` / `"deny"` (human-readable; common for `log_format` and access-log filters)
  - `$cedar_decision` — `"1"` / `"0"` (machine-readable; useful for `map` / Lua dispatch)
  - `$cedar_policy_id` — the `@id` annotation of the first matched policy (so operators can name policies for audit trails)
  - `$cedar_advice` — the `@advice` annotation of the first matched policy (so policies can attach a human-readable reason that ends up in logs without reverse-mapping from a numeric ID)
