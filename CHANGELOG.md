# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **BREAKING**: The PRECONTENT-phase handler now reports its allow decision with `NGX_DECLINED` instead of `NGX_OK`
  - Under nginx's generic phase checker, `NGX_OK` tells the phase engine "this phase is fully done", which silently skipped every other PRECONTENT-phase handler registered in the same location (`try_files`, `mirror`, other authorization modules) whenever this module allowed a request; `NGX_DECLINED` lets those handlers run as configured, matching how any other well-behaved phase handler is expected to behave
  - The deny path is unaffected: a denied request still returns the configured `auth_cedar_deny_status` immediately
- The module now registers its PRECONTENT-phase handler at a fixed priority via the new `nxe-phase` submodule instead of relying on module load order, so its position relative to other handlers registered through `nxe-phase` in the same phase no longer depends on `load_module` ordering in `nginx.conf`; handlers at the same priority still run in registration order, and handlers registered directly with nginx (not via `nxe-phase`) are outside this ordering guarantee

### Dependencies

- Add the `nxe-phase` submodule to 0.1.0 (shared phase-handler-ordering helper)

## [0.3.0] - 2026-06-01

### Added

- New Cedar language capabilities are now usable in policies, via the `nxe-cedar` 0.3.0 evaluator
  - `datetime` / `duration` extension types — construction, normalization, methods, and comparison; malformed forms deny rather than evaluate
  - Total `==` / `!=` over type mismatch, so comparing values of different types yields a defined boolean instead of an error
  - Attribute access, `has`, and `in` resolution on request entity literals (`principal` / `resource`)
  - Bare `context` materialized as a whole record value, supporting self-comparison, `has`, `!=`, and record-literal equality

### Dependencies

- Bump the `nxe-cedar` submodule from 0.2.1 to 0.3.0

## [0.2.0] - 2026-05-28

### Changed

- **BREAKING**: `auth_cedar_policy_file` and `auth_cedar` require explicit policy ids
  - `auth_cedar_policy_file <id> <file> [<file>...]` declares a named policy set under a non-reserved id (`[A-Za-z0-9_-]+`); the old single-argument form (`auth_cedar_policy_file <path>;`) is no longer accepted, and the id namespace is unique across the http block so the same id cannot be declared twice
  - `auth_cedar` now takes `on` (apply the union of every declared id), `off` (skip the handler), or a whitespace-separated list of ids (apply only the listed sets); `on`/`off` are reserved and cannot be used as ids, mixed with ids, or repeated, and every cross-reference is resolved at configuration time so an undeclared id or `auth_cedar on` without any policy file aborts `nginx -t` / startup with an `emerg` message rather than failing per request
  - Policy selection is resolved into a per-location `nxe_cedar_policy_set_t` in `merge_loc_conf` and shared across `auth_cedar on` locations via a single union built once in `init_main_conf`; the nxe-cedar evaluator is unchanged because the union of policy sets is still a single policy set, so the forbid-priority decision model continues to apply unmodified

## [0.1.0] - 2026-05-27

### Added

#### NGINX module

- Initial release of the `ngx_http_auth_cedar_module` dynamic module — a Cedar-based authorization (AuthZ) handler that evaluates a policy set against each request at the PRECONTENT phase
  - The handler runs after the access phase (so it sees the post-rewrite URI and the variables that `auth_jwt` / `auth_oauth2_token` / `auth_request` have already populated) and before the content phase (so policy decisions cannot be bypassed by a content handler that short-circuits earlier); a per-request `ngx_http_auth_cedar_ctx_t` caches the decision and the matching policy details so subsequent re-entries on the same request reuse the result instead of re-evaluating
  - The cached decision records the `loc_conf` it evaluated against, so a request that lands in a different location through an internal redirect (`error_page = /elsewhere`, `try_files`, named-location) is re-evaluated against the destination's mappings instead of carrying a permissive decision into a stricter location; genuine re-entry into the same location still takes the fast path
  - Policy evaluation flows through `nxe_cedar_eval_detail()` so the matched policies are kept on the request pool; the diagnostics are then surfaced through the `$cedar_policy_id` / `$cedar_advice` variables for audit logging without forcing the caller to re-parse the policy text

#### Directives

- `auth_cedar_policy_file <path>` (http) loads a Cedar policy file at configuration time, parses it onto the configuration pool via `nxe_cedar_parse()`, and merges its policies into a single policy set; the directive may be repeated to compose multiple files, and any single payload is capped at 16 MiB so a misconfigured or malicious file is rejected with its size in the `emerg` log rather than expanding the configuration pool without bound
- `auth_cedar on|off` (server / location / `if`) toggles enforcement for the location; merging follows the standard nginx flag semantics, defaulting to off
- `auth_cedar_principal_id <value>` (server / location) overrides the identifier of the `principal` entity with a complex value, so the principal can be sourced from any nginx variable (`$jwt_claim_sub`, `$oauth2_username`, `$arg_*`, a `map`-rewritten value, …) rather than the `r->headers_in.user` field that only `ngx_http_auth_basic_module` populates; without the directive the principal id falls back to `r->headers_in.user`, and compositions such as `auth_cedar_principal_id "${jwt_claim_iss}|${jwt_claim_sub}"` are valid
- `auth_cedar_principal_attr <name> <value>` / `auth_cedar_resource_attr` / `auth_cedar_context_attr` (server / location, may be repeated) bind a Cedar entity attribute to any nginx variable / complex value; mappings stack up the configuration hierarchy and the evaluator pulls the current value at request time via `ngx_http_complex_value()`, so anything the access phase publishes (`$jwt_claim_*`, `$oauth2_*`, `$arg_*`, `map`, Lua, …) is reachable from policies as `principal.X` / `resource.X` / `context.X`; a duplicate attribute name within the same scope is rejected at configuration time with an `emerg` message rather than turning every request into a `500`
- `auth_cedar_resource_type <type>` (server / location, default `Resource`) selects the entity type of the `resource` so policies can use `resource is Article` / `resource is Endpoint` to discriminate locations from a single shared policy file
- `auth_cedar_deny_status <code>` (server / location, default `403`) overrides the HTTP status returned on deny; useful when downstream tooling distinguishes authorization failures by code (e.g. 401 to trigger a re-auth redirect)

#### Entity construction

- Entity construction from the nginx request (`ngx_auth_cedar_entity.c`)
  - `principal` is `User::"<principal id>"` (sourced from `auth_cedar_principal_id`, falling back to `r->headers_in.user`, or the empty string when neither is set); `action` is `Action::"<HTTP method>"`; `resource` is `<resource_type>::"<URI>"` so URI-prefix policies like `resource.path like "/admin/*"` (where `path` is the user-supplied resource attribute) work without further configuration
  - `context.ip` is auto-injected from `$remote_addr` for convenience (matches the most common policy idiom `ip("10.0.0.0/8").contains(context.ip)`); the auto-injection is skipped when the operator explicitly maps `ip` via `auth_cedar_context_attr` (e.g. to trust `X-Forwarded-For` through the `realip` module), avoiding the duplicate-key rejection that `nxe-cedar` enforces on attribute injection
  - Empty variable values are dropped from the entity rather than injected as an empty string, so `principal has role` reflects the actual presence of the claim instead of always being `true`

#### Variables

- Result-exposing nginx variables (`ngx_auth_cedar_variable.c`), all marked `NGX_HTTP_VAR_NOCACHEABLE` so log subrequests see the live decision
  - `$cedar_result` — `"allow"` / `"deny"` (human-readable; common for `log_format` and access-log filters)
  - `$cedar_decision` — `"1"` / `"0"` (machine-readable; useful for `map` / Lua dispatch)
  - `$cedar_policy_id` — the `@id` annotation of the first matched policy (so operators can name policies for audit trails)
  - `$cedar_advice` — the `@advice` annotation of the first matched policy (so policies can attach a human-readable reason that ends up in logs without reverse-mapping from a numeric ID)
