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
    ngx_flag_t   enable;
    ngx_str_t    resource_type;
    ngx_array_t *principal_attrs;                   /* array of
                                                       ngx_auth_cedar_attr_mapping_t */
    ngx_array_t *resource_attrs;                    /* array of
                                                       ngx_auth_cedar_attr_mapping_t */
    ngx_array_t *context_attrs;                     /* array of
                                                       ngx_auth_cedar_attr_mapping_t */
    ngx_uint_t   deny_status;
} ngx_http_auth_cedar_loc_conf_t;


/* per-request context */
typedef struct {
    nxe_cedar_decision_t         decision;
    nxe_cedar_decision_detail_t  detail;
    unsigned                     evaluated:1;
} ngx_http_auth_cedar_ctx_t;


#endif /* NGX_HTTP_AUTH_CEDAR_MODULE_H */
