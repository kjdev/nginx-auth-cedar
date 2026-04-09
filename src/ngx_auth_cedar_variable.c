/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_cedar_variable.c - nginx variable providers for Cedar results
 */

#include "ngx_auth_cedar_variable.h"
#include "ngx_http_auth_cedar_module.h"


static ngx_int_t ngx_auth_cedar_result_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_auth_cedar_decision_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_auth_cedar_annotation_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);


static ngx_str_t ngx_auth_cedar_annotation_id =
    ngx_string("id");
static ngx_str_t ngx_auth_cedar_annotation_advice =
    ngx_string("advice");


static ngx_http_variable_t ngx_auth_cedar_vars[] = {

    { ngx_string("cedar_result"),
      NULL,
      ngx_auth_cedar_result_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("cedar_decision"),
      NULL,
      ngx_auth_cedar_decision_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("cedar_policy_id"),
      NULL,
      ngx_auth_cedar_annotation_variable,
      (uintptr_t) &ngx_auth_cedar_annotation_id,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("cedar_advice"),
      NULL,
      ngx_auth_cedar_annotation_variable,
      (uintptr_t) &ngx_auth_cedar_annotation_advice,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_auth_cedar_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_cedar_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cedar_module);

    if (ctx == NULL || !ctx->evaluated) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->decision == NXE_CEDAR_DECISION_ALLOW) {
        v->data = (u_char *) "allow";
        v->len = sizeof("allow") - 1;
    } else {
        v->data = (u_char *) "deny";
        v->len = sizeof("deny") - 1;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_cedar_decision_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_cedar_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cedar_module);

    if (ctx == NULL || !ctx->evaluated) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->decision == NXE_CEDAR_DECISION_ALLOW) {
        v->data = (u_char *) "1";
        v->len = 1;
    } else {
        v->data = (u_char *) "0";
        v->len = 1;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_cedar_annotation_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_cedar_ctx_t *ctx;
    ngx_str_t *key, *value;
    nxe_cedar_policy_t *policy;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cedar_module);

    if (ctx == NULL || !ctx->evaluated
        || ctx->detail.npolicies == 0
        || ctx->detail.policies == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    key = (ngx_str_t *) data;
    policy = ctx->detail.policies[0];

    value = nxe_cedar_policy_get_annotation(policy, key);

    if (value == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = value->data;
    v->len = value->len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


ngx_int_t
ngx_auth_cedar_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_auth_cedar_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
