/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_http_auth_cedar_module.c - Cedar policy authorization module
 */


#include "ngx_http_auth_cedar_module.h"
#include "ngx_auth_cedar_entity.h"
#include "ngx_auth_cedar_variable.h"


static ngx_int_t ngx_http_auth_cedar_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_cedar_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_cedar_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_auth_cedar_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_auth_cedar_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_cedar_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_auth_cedar_policy_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_principal_id(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_attr(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_deny_status(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_auth_cedar_commands[] = {

    { ngx_string("auth_cedar"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cedar_loc_conf_t, enable),
      NULL },

    { ngx_string("auth_cedar_policy_file"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_cedar_policy_file,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_cedar_principal_id"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_cedar_principal_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_cedar_principal_attr"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_auth_cedar_attr,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cedar_loc_conf_t, principal_attrs),
      NULL },

    { ngx_string("auth_cedar_resource_type"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cedar_loc_conf_t, resource_type),
      NULL },

    { ngx_string("auth_cedar_resource_attr"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_auth_cedar_attr,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cedar_loc_conf_t, resource_attrs),
      NULL },

    { ngx_string("auth_cedar_context_attr"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_auth_cedar_attr,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cedar_loc_conf_t, context_attrs),
      NULL },

    { ngx_string("auth_cedar_deny_status"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_cedar_deny_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_auth_cedar_module_ctx = {
    ngx_http_auth_cedar_preconfiguration,   /* preconfiguration */
    ngx_http_auth_cedar_postconfiguration,  /* postconfiguration */

    ngx_http_auth_cedar_create_main_conf,   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_auth_cedar_create_loc_conf,    /* create location configuration */
    ngx_http_auth_cedar_merge_loc_conf      /* merge location configuration */
};


ngx_module_t ngx_http_auth_cedar_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_cedar_module_ctx,        /* module context */
    ngx_http_auth_cedar_commands,           /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_cedar_handler(ngx_http_request_t *r)
{
    ngx_http_auth_cedar_loc_conf_t *lcf;
    ngx_http_auth_cedar_main_conf_t *mcf;
    ngx_http_auth_cedar_ctx_t *ctx;
    nxe_cedar_eval_ctx_t *eval_ctx;
    nxe_cedar_decision_t decision;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cedar_module);

    if (!lcf->enable) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_main_conf(r,
                                        ngx_http_auth_cedar_module);

    if (mcf->policy_set == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cedar: no policy file configured");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cedar_module);

    /* Reuse the cached decision only when we are re-entering for the
       same location. After an internal redirect to a different location
       (e.g. via `error_page 403 = /other`) the lcf differs and the
       policy set must be evaluated against the new location's
       attribute mappings. */
    if (ctx != NULL && ctx->evaluated && ctx->last_lcf == lcf) {
        if (ctx->decision == NXE_CEDAR_DECISION_ALLOW) {
            return NGX_OK;
        }

        return lcf->deny_status;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_cedar_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_auth_cedar_module);
    }

    eval_ctx = nxe_cedar_eval_ctx_create(r->pool);
    if (eval_ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_auth_cedar_entity_resolve(r, lcf, eval_ctx,
                                      &ctx->principal_id)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    decision = nxe_cedar_eval_detail(mcf->policy_set, eval_ctx,
                                     r->connection->log,
                                     &ctx->detail);

    ctx->decision = decision;
    ctx->evaluated = 1;
    ctx->last_lcf = lcf;

    if (decision == NXE_CEDAR_DECISION_ALLOW) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "cedar: access denied for \"%V %V\","
                  " principal=\"%V\", client=%V",
                  &r->method_name, &r->uri,
                  &ctx->principal_id,
                  &r->connection->addr_text);

    return lcf->deny_status;
}


static ngx_int_t
ngx_http_auth_cedar_preconfiguration(ngx_conf_t *cf)
{
    return ngx_auth_cedar_add_variables(cf);
}


static ngx_int_t
ngx_http_auth_cedar_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_cedar_handler;

    return NGX_OK;
}


static void *
ngx_http_auth_cedar_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_cedar_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_auth_cedar_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_auth_cedar_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_cedar_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_auth_cedar_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->deny_status = NGX_CONF_UNSET_UINT;

    conf->principal_id = NGX_CONF_UNSET_PTR;
    conf->principal_attrs = NGX_CONF_UNSET_PTR;
    conf->resource_attrs = NGX_CONF_UNSET_PTR;
    conf->context_attrs = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_auth_cedar_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_auth_cedar_loc_conf_t *prev = parent;
    ngx_http_auth_cedar_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_str_value(conf->resource_type,
                             prev->resource_type, "Resource");

    ngx_conf_merge_ptr_value(conf->principal_id,
                             prev->principal_id, NULL);
    ngx_conf_merge_ptr_value(conf->principal_attrs,
                             prev->principal_attrs, NULL);
    ngx_conf_merge_ptr_value(conf->resource_attrs,
                             prev->resource_attrs, NULL);
    ngx_conf_merge_ptr_value(conf->context_attrs,
                             prev->context_attrs, NULL);

    ngx_conf_merge_uint_value(conf->deny_status,
                              prev->deny_status, 403);

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_cedar_policy_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cedar_main_conf_t *mcf = conf;

    ngx_str_t *value, file_path;
    u_char *p, *data;
    size_t size;
    ssize_t n;
    ngx_fd_t fd;
    ngx_file_t file;
    ngx_file_info_t fi;
    ngx_str_t text;
    nxe_cedar_policy_set_t *pset;
    nxe_cedar_policy_t *src, *dst;
    ngx_uint_t i;

    value = cf->args->elts;
    file_path = value[1];

    if (ngx_conf_full_name(cf->cycle, &file_path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    p = ngx_pnalloc(cf->pool, file_path.len + 1);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(p, file_path.data, file_path.len);
    p[file_path.len] = '\0';
    file_path.data = p;

    fd = ngx_open_file(file_path.data, NGX_FILE_RDONLY,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed",
                           &file_path);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed",
                           &file_path);
        goto failed;
    }

    size = (size_t) ngx_file_size(&fi);

    if (size > NGX_HTTP_AUTH_CEDAR_MAX_POLICY_FILE_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cedar policy file \"%V\" is %uz bytes,"
                           " exceeds the %uz byte limit",
                           &file_path, size,
                           (size_t)
                           NGX_HTTP_AUTH_CEDAR_MAX_POLICY_FILE_SIZE);
        goto failed;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = file_path;
    file.log = cf->log;

    if (size > 0) {
        data = ngx_pnalloc(cf->pool, size);
        if (data == NULL) {
            goto failed;
        }

        n = ngx_read_file(&file, data, size, 0);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_read_file_n " \"%V\" failed",
                               &file_path);
            goto failed;
        }

        if ((size_t) n != size) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" was truncated",
                               &file_path);
            goto failed;
        }

        text.data = data;
        text.len = size;

    } else {
        ngx_str_set(&text, "");
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &file_path);
    }

    pset = nxe_cedar_parse(cf->pool, cf->log, &text);
    if (pset == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cedar policy parse failed \"%V\"",
                           &file_path);
        return NGX_CONF_ERROR;
    }

    if (mcf->policy_set == NULL) {
        mcf->policy_set = pset;
        return NGX_CONF_OK;
    }

    if (pset->policies == NULL || pset->policies->nelts == 0) {
        return NGX_CONF_OK;
    }

    /* A previously loaded policy set may have parsed to an empty
       (NULL) policies array if the first file was blank; promote the
       incoming array in that case rather than dereferencing a NULL. */
    if (mcf->policy_set->policies == NULL) {
        mcf->policy_set->policies = pset->policies;
        return NGX_CONF_OK;
    }

    src = pset->policies->elts;

    for (i = 0; i < pset->policies->nelts; i++) {
        dst = ngx_array_push(mcf->policy_set->policies);
        if (dst == NULL) {
            return NGX_CONF_ERROR;
        }

        *dst = src[i];
    }

    return NGX_CONF_OK;

failed:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &file_path);
    }

    return NGX_CONF_ERROR;
}


static char *
ngx_http_auth_cedar_attr(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char *p = conf;

    ngx_array_t **app;
    ngx_str_t *value;
    ngx_auth_cedar_attr_mapping_t *attr, *existing;
    ngx_http_compile_complex_value_t ccv;
    ngx_uint_t i;

    app = (ngx_array_t **) (p + cmd->offset);

    if (*app == NGX_CONF_UNSET_PTR) {
        *app = ngx_array_create(cf->pool, 4,
                                sizeof(ngx_auth_cedar_attr_mapping_t));
        if (*app == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    /* Reject duplicate names at configuration time: the nxe-cedar
       evaluator rejects a second add for the same attribute and would
       otherwise turn this misconfiguration into a per-request 500. */
    existing = (*app)->elts;
    for (i = 0; i < (*app)->nelts; i++) {
        if (existing[i].name.len == value[1].len
            && ngx_strncmp(existing[i].name.data, value[1].data,
                           value[1].len)
               == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"%V\" name \"%V\"",
                               &cmd->name, &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    attr = ngx_array_push(*app);
    if (attr == NULL) {
        return NGX_CONF_ERROR;
    }

    attr->name = value[1];

    attr->value = ngx_palloc(cf->pool,
                             sizeof(ngx_http_complex_value_t));
    if (attr->value == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = attr->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_cedar_principal_id(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cedar_loc_conf_t *lcf = conf;

    ngx_str_t *value;
    ngx_http_compile_complex_value_t ccv;

    if (lcf->principal_id != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lcf->principal_id = ngx_palloc(cf->pool,
                                   sizeof(ngx_http_complex_value_t));
    if (lcf->principal_id == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = lcf->principal_id;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_cedar_deny_status(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cedar_loc_conf_t *lcf = conf;

    ngx_int_t n;
    ngx_str_t *value;

    if (lcf->deny_status != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n < 400 || n > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid status code \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->deny_status = (ngx_uint_t) n;

    return NGX_CONF_OK;
}
