/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_http_auth_cedar_module.c - Cedar policy authorization module
 */


#include "nxe_phase.h"

#include "ngx_http_auth_cedar_module.h"
#include "ngx_auth_cedar_entity.h"
#include "ngx_auth_cedar_variable.h"


static ngx_int_t ngx_http_auth_cedar_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_cedar_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_cedar_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_auth_cedar_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_auth_cedar_init_main_conf(ngx_conf_t *cf,
    void *conf);
static void *ngx_http_auth_cedar_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_cedar_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_auth_cedar(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_policy_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_principal_id(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_attr(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_cedar_deny_status(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_cedar_validate_id(ngx_str_t *id);
static nxe_cedar_policy_set_t *ngx_http_auth_cedar_new_policy_set(
    ngx_conf_t *cf);
static nxe_cedar_policy_set_t *ngx_http_auth_cedar_parse_file(
    ngx_conf_t *cf, ngx_str_t *path);
static ngx_int_t ngx_http_auth_cedar_append_policies(ngx_conf_t *cf,
    nxe_cedar_policy_set_t *dst, nxe_cedar_policy_set_t *src);
static ngx_http_auth_cedar_named_policy_t *
    ngx_http_auth_cedar_find_named(
    ngx_http_auth_cedar_main_conf_t *mcf, ngx_str_t *id);
static nxe_cedar_policy_set_t *ngx_http_auth_cedar_build_selected(
    ngx_conf_t *cf, ngx_http_auth_cedar_main_conf_t *mcf,
    ngx_array_t *policy_ids, ngx_str_t *loc_name);


static ngx_command_t ngx_http_auth_cedar_commands[] = {

    { ngx_string("auth_cedar"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_1MORE,
      ngx_http_auth_cedar,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_cedar_policy_file"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE,
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
    ngx_http_auth_cedar_init_main_conf,     /* init main configuration */

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
    ngx_http_auth_cedar_ctx_t *ctx;
    nxe_cedar_eval_ctx_t *eval_ctx;
    nxe_cedar_decision_t decision;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cedar_module);

    if (lcf->mode == NGX_HTTP_AUTH_CEDAR_MODE_OFF
        || lcf->mode == NGX_HTTP_AUTH_CEDAR_MODE_UNSET)
    {
        return NGX_DECLINED;
    }

    /* Defensive fail-closed: merge_loc_conf must populate
       resolved_policy_set whenever mode is ON or SELECTIVE, but if
       that invariant is ever broken we refuse the request instead of
       silently bypassing authorization. */
    if (lcf->resolved_policy_set == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cedar: resolved_policy_set is NULL"
                      " (mode=%ui); refusing to fail open",
                      lcf->mode);
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
            /* PRECONTENT uses generic phase checker: NGX_DECLINED =
               next handler */
            return NGX_DECLINED;
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

    decision = nxe_cedar_eval_detail(lcf->resolved_policy_set, eval_ctx,
                                     r->connection->log,
                                     &ctx->detail);

    ctx->decision = decision;
    ctx->evaluated = 1;
    ctx->last_lcf = lcf;

    if (decision == NXE_CEDAR_DECISION_ALLOW) {
        /* PRECONTENT uses generic phase checker: NGX_DECLINED =
           next handler */
        return NGX_DECLINED;
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
    if (nxe_phase_add_handler(cf, NGX_HTTP_PRECONTENT_PHASE,
                              NXE_PHASE_PRIO_CEDAR,
                              ngx_http_auth_cedar_handler,
                              "auth_cedar") != NGX_OK)
    {
        return NGX_ERROR;
    }

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


static char *
ngx_http_auth_cedar_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_auth_cedar_main_conf_t *mcf = conf;
    ngx_http_auth_cedar_named_policy_t *named;
    ngx_uint_t i;

    if (mcf->named_policy_sets == NULL
        || mcf->named_policy_sets->nelts == 0)
    {
        /* No auth_cedar_policy_file directives were given. Locations
           that try to enable auth_cedar will be rejected later in
           merge_loc_conf when they fail to resolve any policy set. */
        return NGX_CONF_OK;
    }

    mcf->all_policy_set = ngx_http_auth_cedar_new_policy_set(cf);
    if (mcf->all_policy_set == NULL) {
        return NGX_CONF_ERROR;
    }

    named = mcf->named_policy_sets->elts;

    for (i = 0; i < mcf->named_policy_sets->nelts; i++) {
        if (ngx_http_auth_cedar_append_policies(cf,
                mcf->all_policy_set, named[i].policy_set)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
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

    /* mode left as NGX_HTTP_AUTH_CEDAR_MODE_UNSET (0) by pcalloc;
       policy_ids and resolved_policy_set also start as NULL. */
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
    ngx_http_auth_cedar_main_conf_t *mcf;
    ngx_http_core_loc_conf_t *clcf;

    /* mode merge: when the child did not set auth_cedar, inherit the
       parent's mode (and the parent's policy_ids if SELECTIVE). When
       neither set anything, default to OFF. */
    if (conf->mode == NGX_HTTP_AUTH_CEDAR_MODE_UNSET) {
        conf->mode = prev->mode;

        if (conf->mode == NGX_HTTP_AUTH_CEDAR_MODE_SELECTIVE
            && conf->policy_ids == NULL)
        {
            conf->policy_ids = prev->policy_ids;
        }

        if (conf->mode == NGX_HTTP_AUTH_CEDAR_MODE_UNSET) {
            conf->mode = NGX_HTTP_AUTH_CEDAR_MODE_OFF;
        }
    }

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

    if (conf->mode == NGX_HTTP_AUTH_CEDAR_MODE_OFF) {
        conf->resolved_policy_set = NULL;
        return NGX_CONF_OK;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_auth_cedar_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (conf->mode == NGX_HTTP_AUTH_CEDAR_MODE_ON) {
        if (mcf->all_policy_set == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"auth_cedar on\" in location \"%V\" "
                          "requires at least one "
                          "\"auth_cedar_policy_file\"",
                          &clcf->name);
            return NGX_CONF_ERROR;
        }
        conf->resolved_policy_set = mcf->all_policy_set;
        return NGX_CONF_OK;
    }

    /* SELECTIVE */
    conf->resolved_policy_set = ngx_http_auth_cedar_build_selected(
        cf, mcf, conf->policy_ids, &clcf->name);
    if (conf->resolved_policy_set == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_cedar_validate_id(ngx_str_t *id)
{
    ngx_uint_t i;
    u_char c;

    if (id->len == 0) {
        return NGX_ERROR;
    }

    /* reserved keywords */
    if (id->len == 2 && ngx_strncmp(id->data, "on", 2) == 0) {
        return NGX_ERROR;
    }
    if (id->len == 3 && ngx_strncmp(id->data, "off", 3) == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < id->len; i++) {
        c = id->data[i];
        if (!((c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9')
              || c == '_'
              || c == '-'))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static nxe_cedar_policy_set_t *
ngx_http_auth_cedar_new_policy_set(ngx_conf_t *cf)
{
    nxe_cedar_policy_set_t *pset;

    pset = ngx_pcalloc(cf->pool, sizeof(nxe_cedar_policy_set_t));
    if (pset == NULL) {
        return NULL;
    }

    pset->policies = ngx_array_create(cf->pool, 4,
                                      sizeof(nxe_cedar_policy_t));
    if (pset->policies == NULL) {
        return NULL;
    }

    return pset;
}


static nxe_cedar_policy_set_t *
ngx_http_auth_cedar_parse_file(ngx_conf_t *cf, ngx_str_t *path)
{
    ngx_str_t file_path;
    u_char *p, *data;
    size_t size;
    ssize_t n;
    ngx_fd_t fd;
    ngx_file_t file;
    ngx_file_info_t fi;
    ngx_str_t text;
    nxe_cedar_policy_set_t *pset;

    file_path = *path;

    if (ngx_conf_full_name(cf->cycle, &file_path, 1) != NGX_OK) {
        return NULL;
    }

    p = ngx_pnalloc(cf->pool, file_path.len + 1);
    if (p == NULL) {
        return NULL;
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
        return NULL;
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
        return NULL;
    }

    return pset;

failed:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &file_path);
    }

    return NULL;
}


static ngx_int_t
ngx_http_auth_cedar_append_policies(ngx_conf_t *cf,
    nxe_cedar_policy_set_t *dst, nxe_cedar_policy_set_t *src)
{
    nxe_cedar_policy_t *s, *d;
    ngx_uint_t i;

    if (src == NULL
        || src->policies == NULL
        || src->policies->nelts == 0)
    {
        return NGX_OK;
    }

    if (dst->policies == NULL) {
        dst->policies = ngx_array_create(cf->pool,
                                         src->policies->nelts,
                                         sizeof(nxe_cedar_policy_t));
        if (dst->policies == NULL) {
            return NGX_ERROR;
        }
    }

    s = src->policies->elts;

    for (i = 0; i < src->policies->nelts; i++) {
        d = ngx_array_push(dst->policies);
        if (d == NULL) {
            return NGX_ERROR;
        }

        *d = s[i];
    }

    return NGX_OK;
}


static ngx_http_auth_cedar_named_policy_t *
ngx_http_auth_cedar_find_named(
    ngx_http_auth_cedar_main_conf_t *mcf, ngx_str_t *id)
{
    ngx_http_auth_cedar_named_policy_t *named;
    ngx_uint_t i;

    if (mcf->named_policy_sets == NULL) {
        return NULL;
    }

    named = mcf->named_policy_sets->elts;

    for (i = 0; i < mcf->named_policy_sets->nelts; i++) {
        if (named[i].id.len == id->len
            && ngx_strncmp(named[i].id.data, id->data, id->len) == 0)
        {
            return &named[i];
        }
    }

    return NULL;
}


static nxe_cedar_policy_set_t *
ngx_http_auth_cedar_build_selected(ngx_conf_t *cf,
    ngx_http_auth_cedar_main_conf_t *mcf, ngx_array_t *policy_ids,
    ngx_str_t *loc_name)
{
    nxe_cedar_policy_set_t *merged;
    ngx_http_auth_cedar_named_policy_t *named;
    ngx_str_t *ids;
    ngx_uint_t i;

    if (policy_ids == NULL || policy_ids->nelts == 0) {
        return NULL;
    }

    ids = policy_ids->elts;

    /* Single id: share the named policy_set pointer so a SELECTIVE
       location with one id costs no extra allocation. */
    if (policy_ids->nelts == 1) {
        named = ngx_http_auth_cedar_find_named(mcf, &ids[0]);
        if (named == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"auth_cedar\" in location \"%V\" "
                          "references undefined policy id \"%V\"",
                          loc_name, &ids[0]);
            return NULL;
        }
        return named->policy_set;
    }

    merged = ngx_http_auth_cedar_new_policy_set(cf);
    if (merged == NULL) {
        return NULL;
    }

    for (i = 0; i < policy_ids->nelts; i++) {
        named = ngx_http_auth_cedar_find_named(mcf, &ids[i]);
        if (named == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"auth_cedar\" in location \"%V\" "
                          "references undefined policy id \"%V\"",
                          loc_name, &ids[i]);
            return NULL;
        }

        if (ngx_http_auth_cedar_append_policies(cf, merged,
                                                named->policy_set)
            != NGX_OK)
        {
            return NULL;
        }
    }

    return merged;
}


static char *
ngx_http_auth_cedar(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cedar_loc_conf_t *lcf = conf;

    ngx_str_t *value, *id_slot;
    ngx_uint_t i, j;

    if (lcf->mode != NGX_HTTP_AUTH_CEDAR_MODE_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    /* "auth_cedar on" / "auth_cedar off" */
    if (cf->args->nelts == 2) {
        if (value[1].len == 2
            && ngx_strncmp(value[1].data, "on", 2) == 0)
        {
            lcf->mode = NGX_HTTP_AUTH_CEDAR_MODE_ON;
            return NGX_CONF_OK;
        }
        if (value[1].len == 3
            && ngx_strncmp(value[1].data, "off", 3) == 0)
        {
            lcf->mode = NGX_HTTP_AUTH_CEDAR_MODE_OFF;
            return NGX_CONF_OK;
        }
    }

    /* Otherwise: every argument is a policy id. Mixing on/off with ids
       is rejected so users do not accidentally write "auth_cedar on
       extra" and assume the extra id had any effect. */
    lcf->policy_ids = ngx_array_create(cf->pool,
                                       cf->args->nelts - 1,
                                       sizeof(ngx_str_t));
    if (lcf->policy_ids == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if ((value[i].len == 2
             && ngx_strncmp(value[i].data, "on", 2) == 0)
            || (value[i].len == 3
                && ngx_strncmp(value[i].data, "off", 3) == 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"on\"/\"off\" cannot be mixed with "
                               "policy ids in \"auth_cedar\"");
            return NGX_CONF_ERROR;
        }

        if (ngx_http_auth_cedar_validate_id(&value[i]) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid policy id \"%V\" in "
                               "\"auth_cedar\" (must match "
                               "[A-Za-z0-9_-]+ and not be a reserved "
                               "keyword)", &value[i]);
            return NGX_CONF_ERROR;
        }

        id_slot = lcf->policy_ids->elts;
        for (j = 0; j < lcf->policy_ids->nelts; j++) {
            if (id_slot[j].len == value[i].len
                && ngx_strncmp(id_slot[j].data, value[i].data,
                               value[i].len)
                   == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate policy id \"%V\" in "
                                   "\"auth_cedar\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        id_slot = ngx_array_push(lcf->policy_ids);
        if (id_slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *id_slot = value[i];
    }

    lcf->mode = NGX_HTTP_AUTH_CEDAR_MODE_SELECTIVE;

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_cedar_policy_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cedar_main_conf_t *mcf = conf;

    ngx_str_t *value;
    ngx_uint_t i;
    nxe_cedar_policy_set_t *pset, *merged;
    ngx_http_auth_cedar_named_policy_t *named;

    value = cf->args->elts;

    if (ngx_http_auth_cedar_validate_id(&value[1]) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid policy id \"%V\" in "
                           "\"auth_cedar_policy_file\" (must match "
                           "[A-Za-z0-9_-]+ and not be a reserved "
                           "keyword \"on\"/\"off\")", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (mcf->named_policy_sets == NULL) {
        mcf->named_policy_sets = ngx_array_create(cf->pool, 4,
            sizeof(ngx_http_auth_cedar_named_policy_t));
        if (mcf->named_policy_sets == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_http_auth_cedar_find_named(mcf, &value[1]) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate policy id \"%V\" in "
                           "\"auth_cedar_policy_file\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    merged = ngx_http_auth_cedar_new_policy_set(cf);
    if (merged == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {
        pset = ngx_http_auth_cedar_parse_file(cf, &value[i]);
        if (pset == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_auth_cedar_append_policies(cf, merged, pset)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    named = ngx_array_push(mcf->named_policy_sets);
    if (named == NULL) {
        return NGX_CONF_ERROR;
    }

    named->id = value[1];
    named->policy_set = merged;

    return NGX_CONF_OK;
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
