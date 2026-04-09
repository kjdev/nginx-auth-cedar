/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_cedar_entity.h - nginx variable to Cedar entity mapping
 */

#ifndef NGX_AUTH_CEDAR_ENTITY_H
#define NGX_AUTH_CEDAR_ENTITY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "nxe_cedar_types.h"
#include "nxe_cedar_eval.h"
#include "ngx_http_auth_cedar_module.h"


/*
 * Build evaluation context from nginx request.
 *
 * Maps nginx variables to Cedar entities:
 *   principal: type="User", id=$remote_user,
 *              attrs from auth_cedar_principal_attr
 *   action:    type="Action", id=$request_method
 *   resource:  type=auth_cedar_resource_type, id=$uri,
 *              attrs from auth_cedar_resource_attr
 *   context:   ip=$remote_addr (auto, unless overridden by user),
 *              attrs from auth_cedar_context_attr
 *
 * Returns NGX_OK on success, NGX_ERROR on failure.
 */
ngx_int_t ngx_auth_cedar_entity_resolve(ngx_http_request_t *r,
    ngx_http_auth_cedar_loc_conf_t *lcf,
    nxe_cedar_eval_ctx_t *ctx);


#endif /* NGX_AUTH_CEDAR_ENTITY_H */
