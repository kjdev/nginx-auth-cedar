/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_cedar_variable.h - nginx variable providers for Cedar results
 */

#ifndef NGX_AUTH_CEDAR_VARIABLE_H
#define NGX_AUTH_CEDAR_VARIABLE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * Register Cedar result variables.
 *
 * Provides:
 *   $cedar_result   - "allow" or "deny"
 *   $cedar_decision - "1" or "0"
 *
 * Called from preconfiguration.
 */
ngx_int_t ngx_auth_cedar_add_variables(ngx_conf_t *cf);


#endif /* NGX_AUTH_CEDAR_VARIABLE_H */
