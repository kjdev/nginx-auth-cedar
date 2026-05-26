# Cedar policy language subset

`nginx-auth-cedar` evaluates policies written in a subset of the
[Cedar policy language](https://www.cedarpolicy.com/). The evaluator
(`nxe-cedar`) is exercised against the official `cedar-policy` Rust
crate via an FFI test oracle, so behavior on supported constructs
matches upstream Cedar for every policy / context pair under
`nxe-cedar/tests/cases/`.

This document is a user-oriented summary. For the exhaustive support
matrix (every operator, type, method, and extension with explicit
Supported / Partial / Not-yet / Out-of-scope status), see
[`nxe-cedar` features](https://github.com/kjdev/nxe-cedar/blob/main/docs/FEATURES.md).

## Policy structure

```
policy      ::= { annotation } effect "(" scope ")" { condition } ";"
effect      ::= "permit" | "forbid"
scope       ::= principal_constraint "," action_constraint "," resource_constraint
condition   ::= ("when" | "unless") "{" expr "}"
annotation  ::= "@" ident [ "(" string ")" ]
```

A policy file contains zero or more policies separated by `;`. Line
comments (`// …`) are supported. Block comments (`/* … */`) are **not**
supported.

```cedar
// Allow admins to do anything.
permit (
    principal,
    action,
    resource
) when {
    principal.role == "admin"
};

// Forbid writes outside business hours.
forbid (
    principal,
    action in [Action::"POST", Action::"PUT", Action::"DELETE"],
    resource
) when {
    context.hour < 9 || context.hour >= 18
};
```

## Evaluation model

Standard Cedar `forbid`-priority evaluation:

1. Every policy in the policy set is evaluated.
2. If any `forbid` matches → **DENY**.
3. Otherwise, if any `permit` matches → **ALLOW**.
4. Otherwise → **DENY** (default deny).

A policy "matches" when:

1. All three scope constraints (`principal`, `action`, `resource`) hold.
2. Every `when` clause evaluates to `true` **and** every `unless` clause
   evaluates to `false`. Multiple clauses are AND-combined.

Evaluation errors (e.g. accessing an attribute that does not exist on
the entity) cause the policy to **not match**. A `forbid` that errors
out therefore does **not** deny on its own — but a `permit` that errors
out does **not** allow either. The forbid-priority rule still applies
across the policy set, so a clean `forbid` elsewhere will still deny.

## Scope constraints

```cedar
permit (
    principal == User::"alice",          // exact match
    action    in [Action::"GET", Action::"HEAD"],
    resource  is Article
);
```

| Constraint | Example | Notes |
| --- | --- | --- |
| Unconstrained | `principal,` | Matches any entity |
| Equality | `principal == Entity::"id"` | Exact identity match |
| Hierarchy | `principal in Role::"editor"` | Caller injects ancestors; reflexive match always succeeds |
| Action set | `action in [Action::"GET", Action::"PUT"]` | Action only; non-entity elements rejected at parse time |
| Type check | `principal is User` | Principal / resource only; rejected on action |
| Type + hierarchy | `principal is User in Role::"editor"` | Combined `is` + `in` form |
| Namespaced type | `principal is MyOrg::User` | Namespaced types accepted |

`nginx-auth-cedar` always sets the principal type to `User` and the
action type to `Action`. The resource type defaults to `Resource` and is
configurable via the `auth_cedar_resource_type` directive (see
[CONFIGURATION.md](CONFIGURATION.md)).

## Built-in variables

| Variable | Cedar type | Source in `nginx-auth-cedar` |
| --- | --- | --- |
| `principal` | entity | `User::"$remote_user"` + `auth_cedar_principal_attr` mappings |
| `action` | entity | `Action::"$request_method"` |
| `resource` | entity | `<resource_type>::"$uri"` + `auth_cedar_resource_attr` mappings |
| `context` | record | `context.ip = $remote_addr` (auto) + `auth_cedar_context_attr` mappings |

## Data types

| Type | Literal / constructor | Notes |
| --- | --- | --- |
| `Bool` | `true`, `false` | |
| `Long` | `42`, `-100` | `int64_t`; arithmetic overflow surfaces as evaluation error |
| `String` | `"hello"` | Escapes `\n` `\r` `\t` `\\` `\"` `\'` `\xHH` `\u{…}`; `\*` only valid inside `like` patterns |
| `Set` | `[1, 2, 3]` | Element types may mix; `==` is order-independent |
| `Record` | `{key: value}` | Up to 64 entries, nesting depth 16; supplied via attribute injection or built inline |
| `Entity` | `Type::"id"`, `NS::Type::"id"` | Namespaced types supported |
| `ipaddr` | `ip("192.0.2.1")`, `ip("10.0.0.0/8")` | IPv4, IPv6, CIDR; dotted IPv4-mapped IPv6 rejected per Cedar spec |
| `decimal` | `decimal("1.23")` | `i64`-backed, scale `10^-4`; range −922 337 203 685 477.5808 to 922 337 203 685 477.5807 |

`datetime` / `duration` are **not** implemented. Pass a precomputed
integer (e.g. an hour-of-day) via the `context` attribute as a
workaround.

## Operators

### Comparison

| Operator | Operand types | Notes |
| --- | --- | --- |
| `==`, `!=` | any matching pair | Sets and records compare order-independently with bijective matching |
| `<`, `<=`, `>`, `>=` | `Long` | Comparing other types is an evaluation error |
| `.lessThan` etc. | `decimal` | Cedar only exposes decimal ordering through these methods |

### Logical

| Operator | Notes |
| --- | --- |
| `&&` | Short-circuits (right operand not evaluated if left is `false`) |
| `\|\|` | Short-circuits (right operand not evaluated if left is `true`) |
| `!` | Boolean negation |
| `if expr then expr else expr` | Only the selected branch is evaluated |

### Arithmetic

| Operator | Operand types | Notes |
| --- | --- | --- |
| `+`, `-`, `*` | `Long` | Overflow → evaluation error |
| `-` (unary) | `Long` | |

### String

| Operator | Notes |
| --- | --- |
| `like` | `*` matches zero or more characters; `\*` escapes a literal `*` |

### Hierarchy

| Form | Notes |
| --- | --- |
| `entity in entity` | Reflexive plus ancestor lookup via injected parents |
| `entity in [entity, …]` | Set right-hand side; all elements must be entities |

### Type check

| Form | Notes |
| --- | --- |
| `expr is Type` | LHS must be entity-typed, else evaluation error |
| `expr is Type in expr` | Combined form |

### Attribute and record access

| Form | Notes |
| --- | --- |
| `expr.ident` | Dot access; requires the attribute to be present |
| `expr["key"]` | Bracket access; the only form for keys that are not valid identifiers (e.g. `"x-real-ip"`) |
| `expr has ident` / `expr has "string"` | Single-key existence check |

## Methods

### Set

| Method | Notes |
| --- | --- |
| `set.contains(elt)` | Argument may be any type; type mismatch returns `false` |
| `set.containsAll(set)` | Both operands must be sets |
| `set.containsAny(set)` | Both operands must be sets |
| `set.isEmpty()` | |

### `ipaddr`

| Method | Notes |
| --- | --- |
| `ip.isInRange(ip)` | Receiver CIDR must be at least as specific as argument range; family mismatch → `false` |
| `ip.isIpv4()` / `ip.isIpv6()` | |
| `ip.isLoopback()` | Receiver entirely within `127.0.0.0/8` or `::1/128` |
| `ip.isMulticast()` | Receiver entirely within `224.0.0.0/4` or `ff00::/8` |

### `decimal`

| Method | Notes |
| --- | --- |
| `decimal.lessThan(decimal)` / `lessThanOrEqual` / `greaterThan` / `greaterThanOrEqual` | i64 comparison on the scaled representation |

## Annotations

Cedar annotations carry metadata that does not affect the policy
decision but is exposed to integrators. `nginx-auth-cedar` surfaces the
`@id` and `@advice` annotations of the first matched policy via the
`$cedar_policy_id` and `$cedar_advice` nginx variables (see
[CONFIGURATION.md](CONFIGURATION.md)).

```cedar
@id("article-author-only")
@advice("only the article author may edit")
forbid (
    principal,
    action == Action::"PUT",
    resource is Article
) unless {
    principal == resource.author
};
```

Up to 16 annotations per policy. Duplicate keys are rejected at parse
time.

## Out-of-scope features

The following Cedar features are intentionally not supported. Where a
workaround exists, it is noted. The full out-of-scope table with
alternatives is in
[`nxe-cedar` features](https://github.com/kjdev/nxe-cedar/blob/main/docs/FEATURES.md).

| Feature | Why / alternative |
| --- | --- |
| `datetime` / `duration` | Not implemented. Precompute an integer (e.g. hour-of-day) and inject it via `auth_cedar_context_attr` |
| Schema validation | Out of scope for runtime evaluation. Validate policies statically with the official Cedar CLI before deploying |
| Template-linked policies (`?principal`, `?resource`) | Static policies suffice for the nginx use case |
| Partial evaluation (`is_authorized_partial`) | All inputs are available at request time |
| External entity store / dynamic hierarchy resolution | The caller injects the transitive closure of ancestors; `nxe-cedar` does not query a store |
| Block comments (`/* … */`) | Use line comments (`// …`) |
| Entity tags (`.hasTag` / `.getTag`) | Use a record-valued attribute instead |

## Limits

These limits keep policy evaluation bounded in the nginx worker. They
are set generously above any realistic policy and surface as
configuration errors (parse time) or evaluation errors (request time)
rather than silent truncation.

| Limit | Value | Scope |
| --- | --- | --- |
| Recursion depth (parser) | 64 | Per expression |
| Recursion depth (evaluator) | 128 | Per request |
| Annotations per policy | 16 | Parse time |
| Record entries | 64 | Per record |
| Record nesting | 16 | Per record |
| Set elements (parser) | 256 | Per set literal in policy text |
| Member access chain | 16 | `a.b.c.d…` depth |

Exceeding these in policy text fails the policy file load; exceeding
them at evaluation time short-circuits the offending expression to an
evaluation error (which, per the model above, means the policy does not
match — equivalent to default-deny if no other policy fires).
