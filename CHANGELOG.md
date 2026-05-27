# Changelog

## [f7cfafa](../../commit/f7cfafa) - 2026-05-28

### Changed

- **BREAKING**: `auth_cedar_policy_file` and `auth_cedar` require explicit policy ids
  - `auth_cedar_policy_file <id> <file> [<file>...]` declares a named policy set under a non-reserved id (`[A-Za-z0-9_-]+`); the old single-argument form (`auth_cedar_policy_file <path>;`) is no longer accepted, and the id namespace is unique across the http block so the same id cannot be declared twice
  - `auth_cedar` now takes `on` (apply the union of every declared id), `off` (skip the handler), or a whitespace-separated list of ids (apply only the listed sets); `on`/`off` are reserved and cannot be used as ids, mixed with ids, or repeated, and every cross-reference is resolved at configuration time so an undeclared id or `auth_cedar on` without any policy file aborts `nginx -t` / startup with an `emerg` message rather than failing per request
  - Policy selection is resolved into a per-location `nxe_cedar_policy_set_t` in `merge_loc_conf` and shared across `auth_cedar on` locations via a single union built once in `init_main_conf`; the nxe-cedar evaluator is unchanged because the union of policy sets is still a single policy set, so the forbid-priority decision model continues to apply unmodified

## [58af33c](../../commit/58af33c) - 2026-05-27

### Fixed

- Reject duplicate attribute names for `auth_cedar_principal_attr` / `auth_cedar_resource_attr` / `auth_cedar_context_attr` at configuration time
  - The `nxe-cedar` evaluator already rejects a second `add` for the same attribute name on a given entity, but the directive handler previously let the duplicate through to request time, where every request then turned into a `500 Internal Server Error` — a silent failure mode that is easy to miss in production
  - The handler now linear-scans the existing entries before pushing a new one and aborts startup with `nginx: [emerg] duplicate "auth_cedar_principal_attr" name "..."` when the directive would introduce a same-scope duplicate; the same name across different scopes (`principal_attr role` + `resource_attr role`) is still allowed since they bind to different entities, and the existing server → location override semantics (child `*_attrs` array replaces parent verbatim) are unchanged

## [4316c20](../../commit/4316c20) - 2026-05-27

### Added

- `auth_cedar_principal_id <value>` directive (server / location) — a complex-value override for the identifier of the `principal` entity, so the principal can be sourced from any nginx variable (`$jwt_claim_sub`, `$oauth2_username`, `$arg_*`, a `map`-rewritten value, …) rather than the `r->headers_in.user` field that only `ngx_http_auth_basic_module` populates (built-in `$remote_user` is not `NGX_HTTP_VAR_CHANGEABLE`, so `auth_request_set $remote_user ...` is rejected at configuration time and cannot feed the fallback)
  - Without the directive, the principal id continues to fall back to `r->headers_in.user` (the previous behavior); a JWT / OAuth2 deployment that never runs Basic Auth no longer silently evaluates every `principal == User::"alice"` policy against an empty id
  - The directive participates in the standard server-to-location merge (child overrides parent) and accepts any complex value, so `auth_cedar_principal_id "${jwt_claim_iss}|${jwt_claim_sub}"` compositions are valid

### Fixed

- Re-evaluate the policy set after an internal redirect lands in a different location (review finding S4)
  - The per-request context now records the `loc_conf` pointer it evaluated against (`ctx->last_lcf`); the cached decision is only reused when the same location re-enters the handler. After an `error_page = /elsewhere`, `try_files`, or named-location redirect the destination's `loc_conf` differs, so the policy set runs again against the destination's `auth_cedar_principal_attr` / `auth_cedar_resource_type` / etc. mappings
  - Closes the bypass where a permissive `/foo` decision could carry into a stricter `/bar` reached through `error_page`, while still preserving the fast path for genuine re-entry into the same location
- Cap a single `auth_cedar_policy_file` payload at 16 MiB (review finding S2)
  - A misconfigured (or malicious) policy file no longer expands the configuration pool without bound. The size is checked before `ngx_pnalloc()` so the rejection happens with the original file size in the `emerg` log message rather than as an opaque OOM
- Guard the multi-file policy merge against a NULL `policies` array on the accumulated set (review finding B1)
  - When an earlier `auth_cedar_policy_file` produced an empty policy set (e.g. a blank file or comments only), the next directive previously dereferenced a NULL `policies->elts` in the append loop; the merge now promotes the incoming array verbatim in that case, so any ordering of empty + non-empty files yields the same policy set
- Drop the redundant block scope around the merge loop (review finding R1) and clear up the `$remote_user`-only documentation that obscured the principal-id source rule

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
