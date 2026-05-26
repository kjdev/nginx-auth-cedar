/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_cedar_entity.c - nginx variable to Cedar entity mapping
 */

#include "ngx_auth_cedar_entity.h"


static ngx_str_t ngx_auth_cedar_user_type =
    ngx_string("User");
static ngx_str_t ngx_auth_cedar_action_type =
    ngx_string("Action");
static ngx_str_t ngx_auth_cedar_ip_attr_name =
    ngx_string("ip");


typedef ngx_int_t (*ngx_auth_cedar_add_attr_fn)(
    nxe_cedar_eval_ctx_t *ctx, ngx_str_t *name,
    ngx_str_t *value);


static ngx_flag_t
ngx_auth_cedar_attrs_have_name(ngx_array_t *mappings, ngx_str_t *name)
{
    ngx_uint_t i;
    ngx_auth_cedar_attr_mapping_t *mapping;

    if (mappings == NULL) {
        return 0;
    }

    mapping = mappings->elts;

    for (i = 0; i < mappings->nelts; i++) {
        if (mapping[i].name.len == name->len
            && ngx_memcmp(mapping[i].name.data, name->data, name->len)
            == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_auth_cedar_resolve_attrs(ngx_http_request_t *r,
    ngx_array_t *mappings, nxe_cedar_eval_ctx_t *ctx,
    ngx_auth_cedar_add_attr_fn add_fn)
{
    ngx_uint_t i;
    ngx_str_t val;
    ngx_auth_cedar_attr_mapping_t *mapping;

    if (mappings == NULL) {
        return NGX_OK;
    }

    mapping = mappings->elts;

    for (i = 0; i < mappings->nelts; i++) {

        if (ngx_http_complex_value(r, mapping[i].value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (val.len == 0) {
            continue;
        }

        if (add_fn(ctx, &mapping[i].name, &val) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_auth_cedar_entity_resolve(ngx_http_request_t *r,
    ngx_http_auth_cedar_loc_conf_t *lcf,
    nxe_cedar_eval_ctx_t *ctx,
    ngx_str_t *principal_id_out)
{
    ngx_str_t principal_id;

    /* principal */

    if (lcf->principal_id != NULL) {
        if (ngx_http_complex_value(r, lcf->principal_id,
                                   &principal_id)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (r->headers_in.user.len > 0) {
        principal_id = r->headers_in.user;

    } else {
        ngx_str_set(&principal_id, "");
    }

    nxe_cedar_eval_ctx_set_principal(ctx,
                                     &ngx_auth_cedar_user_type,
                                     &principal_id);

    if (principal_id_out != NULL) {
        *principal_id_out = principal_id;
    }

    if (ngx_auth_cedar_resolve_attrs(r, lcf->principal_attrs,
                                     ctx,
                                     nxe_cedar_eval_ctx_add_principal_attr)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* action */

    nxe_cedar_eval_ctx_set_action(ctx,
                                  &ngx_auth_cedar_action_type,
                                  &r->method_name);

    /* resource */

    nxe_cedar_eval_ctx_set_resource(ctx,
                                    &lcf->resource_type,
                                    &r->uri);

    if (ngx_auth_cedar_resolve_attrs(r, lcf->resource_attrs,
                                     ctx,
                                     nxe_cedar_eval_ctx_add_resource_attr)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* context */

    /*
     * Auto-inject $remote_addr as `context.ip` unless the user has
     * provided their own ip mapping (e.g. trusting X-Forwarded-For via
     * the real_ip module). Since nxe-cedar 0.1.0 rejects duplicate
     * attribute names, both calls cannot coexist.
     */
    if (!ngx_auth_cedar_attrs_have_name(lcf->context_attrs,
                                        &ngx_auth_cedar_ip_attr_name))
    {
        if (nxe_cedar_eval_ctx_add_context_attr(
                ctx, &ngx_auth_cedar_ip_attr_name,
                &r->connection->addr_text)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_auth_cedar_resolve_attrs(r, lcf->context_attrs,
                                     ctx,
                                     nxe_cedar_eval_ctx_add_context_attr)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
