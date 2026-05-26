/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_http_auth_cedar_module.h - Cedar policy authorization module
 */

#ifndef NGX_HTTP_AUTH_CEDAR_MODULE_H
#define NGX_HTTP_AUTH_CEDAR_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "nxe_cedar_types.h"
#include "nxe_cedar_parser.h"
#include "nxe_cedar_eval.h"


extern ngx_module_t ngx_http_auth_cedar_module;


/* Hard cap on a single auth_cedar_policy_file payload, to prevent a
   misconfiguration from exhausting the configuration pool at startup. */
#define NGX_HTTP_AUTH_CEDAR_MAX_POLICY_FILE_SIZE \
        (16 * 1024 * 1024)


/* principal attribute mapping: name -> nginx variable */
typedef struct {
    ngx_str_t                 name;
    ngx_http_complex_value_t *value;
} ngx_auth_cedar_attr_mapping_t;


/* http main configuration */
typedef struct {
    nxe_cedar_policy_set_t *policy_set;
} ngx_http_auth_cedar_main_conf_t;


/* location configuration */
typedef struct {
    ngx_flag_t                enable;
    ngx_str_t                 resource_type;
    ngx_http_complex_value_t *principal_id;         /* override for the
                                                       principal entity id
                                                       (defaults to
                                                       r->headers_in.user
                                                       from auth_basic) */
    ngx_array_t              *principal_attrs;      /* array of
                                                       ngx_auth_cedar_attr_mapping_t */
    ngx_array_t              *resource_attrs;       /* array of
                                                       ngx_auth_cedar_attr_mapping_t */
    ngx_array_t              *context_attrs;        /* array of
                                                       ngx_auth_cedar_attr_mapping_t */
    ngx_uint_t                deny_status;
} ngx_http_auth_cedar_loc_conf_t;


/* per-request context.
   `last_lcf` is the cache key for re-entry: a request that internally
   redirects to a different location (e.g. via `error_page = /other`)
   lands here again with a different `lcf`, so the previous decision
   must be discarded and the policy set re-evaluated against the new
   location's mappings.
   `principal_id` is the identifier that was actually fed to the
   evaluator (after the auth_cedar_principal_id override resolves), so
   the deny log can quote what the policy saw rather than the raw
   $remote_user. */
typedef struct {
    nxe_cedar_decision_t            decision;
    nxe_cedar_decision_detail_t     detail;
    ngx_http_auth_cedar_loc_conf_t *last_lcf;
    ngx_str_t                       principal_id;
    unsigned                        evaluated:1;
} ngx_http_auth_cedar_ctx_t;


#endif /* NGX_HTTP_AUTH_CEDAR_MODULE_H */
