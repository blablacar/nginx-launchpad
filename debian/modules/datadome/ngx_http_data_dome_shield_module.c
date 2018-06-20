#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if !defined(nginx_version) && (nginx_version < 1005006)
#include <ctype.h>
#endif


#define MAX_PARAM_DATALEN (10 * 1024)

typedef struct {
  ngx_array_t                   *flushes;
  ngx_array_t                   *lengths;
  ngx_array_t                   *values;
} ngx_http_data_dome_shield_params_t;


typedef struct {
  ngx_str_t                      key;

  ngx_str_t                      cookie;

  ngx_flag_t                     debug_params;

  ngx_array_t                   *params_source;

  ngx_http_data_dome_shield_params_t params;

} ngx_http_data_dome_shield_loc_conf_t;


typedef struct {
  ngx_str_t     client_id;
} ngx_http_data_dome_shield_ctx_t;


static ngx_int_t ngx_http_data_dome_shield_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_request_body_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_timestamp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_url_encode_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, int limit, int from_end);
static ngx_int_t ngx_http_data_dome_shield_client_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_request(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data, int limit);
static ngx_int_t ngx_http_data_dome_shield_http_variable_request_2048(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data, int limit);
static ngx_int_t ngx_http_data_dome_shield_http_variable_header_1024(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_header_768(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_header_512(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_unknown_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part, int limit, int from_end);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_x_forwarded_for(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_accept(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_accept_charset(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_accept_encoding(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_accept_language(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_x_requested_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_origin(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_pragma(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_cache_control(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_content_type(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_from(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_x_real_ip(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_via(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_http_true_client_ip(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_header_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part);
static ngx_int_t ngx_http_data_dome_shield_http_variable_header_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part);
static ngx_int_t ngx_http_data_dome_shield_http_variable_cookies_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_authorization_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_post_param_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_shield_http_variable_headers_list(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_data_dome_shield_add_variables(ngx_conf_t *cf);

static void *ngx_http_data_dome_shield_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_data_dome_shield_merge_loc_conf(ngx_conf_t *cf,
						      void *parent, void *child);

static ngx_int_t
ngx_http_data_dome_shield_init_params(ngx_conf_t *cf, ngx_http_data_dome_shield_loc_conf_t *conf,
    ngx_http_data_dome_shield_params_t *params, ngx_keyval_t *default_params, ngx_keyval_t *debug_params);


static ngx_command_t  ngx_http_data_dome_shield_commands[] = {

  { ngx_string("data_dome_shield_key"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_data_dome_shield_loc_conf_t, key),
    NULL },

  { ngx_string("data_dome_shield_cookie"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_data_dome_shield_loc_conf_t, cookie),
    NULL },

  { ngx_string("data_dome_shield_set_param"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_data_dome_shield_loc_conf_t, params_source),
    NULL },

  { ngx_string("data_dome_shield_debug_params"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_data_dome_shield_loc_conf_t, debug_params),
    NULL },

  ngx_null_command
};


static ngx_http_module_t  ngx_http_data_dome_shield_module_ctx = {
  ngx_http_data_dome_shield_add_variables,   /* preconfiguration */
  NULL,                                      /* postconfiguration */

  NULL,                                      /* create main configuration */
  NULL,                                      /* init main configuration */

  NULL,                                      /* create server configuration */
  NULL,                                      /* merge server configuration */

  ngx_http_data_dome_shield_create_loc_conf, /* create location configuration */
  ngx_http_data_dome_shield_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_data_dome_shield_module = {
  NGX_MODULE_V1,
  &ngx_http_data_dome_shield_module_ctx, /* module context */
  ngx_http_data_dome_shield_commands,    /* module directives */
  NGX_HTTP_MODULE,                       /* module type */
  NULL,                                  /* init master */
  NULL,                                  /* init module */
  NULL,                                  /* init process */
  NULL,                                  /* init thread */
  NULL,                                  /* exit thread */
  NULL,                                  /* exit process */
  NULL,                                  /* exit master */
  NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_data_dome_shield_vars[] = {

  { ngx_string("data_dome_key"), NULL,
    ngx_http_data_dome_shield_key_variable, 0,
    NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

  { ngx_string("data_dome_request_body"), NULL,
    ngx_http_data_dome_shield_request_body_variable, 0,
    NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

  { ngx_string("data_dome_timestamp"), NULL,
    ngx_http_data_dome_shield_timestamp_variable, 0,
    NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

  { ngx_string("data_dome_client_id"), NULL,
    ngx_http_data_dome_shield_client_id_variable, 0,
    NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

  { ngx_string("data_dome_http_user_agent"), NULL,
    ngx_http_data_dome_shield_http_variable_header_768,
    offsetof(ngx_http_request_t, headers_in.user_agent), 0, 0 },

  { ngx_string("data_dome_http_host"), NULL,
    ngx_http_data_dome_shield_http_variable_header_512,
    offsetof(ngx_http_request_t, headers_in.host), 0, 0 },

  { ngx_string("data_dome_http_referer"), NULL,
    ngx_http_data_dome_shield_http_variable_header_1024,
    offsetof(ngx_http_request_t, headers_in.referer), 0, 0 },

  { ngx_string("data_dome_request_uri"), NULL,
    ngx_http_data_dome_shield_http_variable_request_2048,
    offsetof(ngx_http_request_t, unparsed_uri), 0, 0 },

  { ngx_string("data_dome_http_x_forwarded_for"), NULL,
    ngx_http_data_dome_shield_http_variable_http_x_forwarded_for,
    0, 0, 0 },

  { ngx_string("data_dome_http_accept"), NULL,
    ngx_http_data_dome_shield_http_variable_http_accept,
    0, 0, 0 },

  { ngx_string("data_dome_http_accept_charset"), NULL,
    ngx_http_data_dome_shield_http_variable_http_accept_charset,
    0, 0, 0 },

  { ngx_string("data_dome_http_accept_encoding"), NULL,
    ngx_http_data_dome_shield_http_variable_http_accept_encoding,
    0, 0, 0 },

  { ngx_string("data_dome_http_accept_language"), NULL,
    ngx_http_data_dome_shield_http_variable_http_accept_language,
    0, 0, 0 },

  { ngx_string("data_dome_http_x_requested_with"), NULL,
    ngx_http_data_dome_shield_http_variable_http_x_requested_with,
    0, 0, 0 },

  { ngx_string("data_dome_http_origin"), NULL,
    ngx_http_data_dome_shield_http_variable_http_origin,
    0, 0, 0 },

  { ngx_string("data_dome_http_connection"), NULL,
    ngx_http_data_dome_shield_http_variable_http_connection,
    0, 0, 0 },

  { ngx_string("data_dome_http_pragma"), NULL,
    ngx_http_data_dome_shield_http_variable_http_pragma,
    0, 0, 0 },

  { ngx_string("data_dome_http_cache_control"), NULL,
    ngx_http_data_dome_shield_http_variable_http_cache_control,
    0, 0, 0 },

  { ngx_string("data_dome_http_content_type"), NULL,
    ngx_http_data_dome_shield_http_variable_http_content_type,
    0, 0, 0 },

  { ngx_string("data_dome_http_from"), NULL,
    ngx_http_data_dome_shield_http_variable_http_from,
    0, 0, 0 },

  { ngx_string("data_dome_http_x_real_ip"), NULL,
    ngx_http_data_dome_shield_http_variable_http_x_real_ip,
    0, 0, 0 },

  { ngx_string("data_dome_http_via"), NULL,
    ngx_http_data_dome_shield_http_variable_http_via,
    0, 0, 0 },

  { ngx_string("data_dome_http_true_client_ip"), NULL,
    ngx_http_data_dome_shield_http_variable_http_true_client_ip,
    0, 0, 0 },

  { ngx_string("data_dome_http_cookie_len"), NULL,
    ngx_http_data_dome_shield_http_variable_cookies_length,
    0, 0, 0 },

  { ngx_string("data_dome_http_authorization_len"), NULL,
    ngx_http_data_dome_shield_http_variable_authorization_length,
    0, 0, 0 },

  { ngx_string("data_dome_post_param_len"), NULL,
    ngx_http_data_dome_shield_http_variable_post_param_len,
    0, 0, 0 },

  { ngx_string("data_dome_headers_list"), NULL,
    ngx_http_data_dome_shield_http_variable_headers_list,
    0, 0, 0 },

  { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_keyval_t  ngx_http_data_dome_params[] = {
    { ngx_string("Key"), ngx_string("$data_dome_key") },
    { ngx_string("UserAgent"), ngx_string("$data_dome_http_user_agent") },
    { ngx_string("IP"), ngx_string("$remote_addr") },
    { ngx_string("Port"), ngx_string("$remote_port") },
    { ngx_string("ClientID"), ngx_string("$data_dome_client_id") },
    { ngx_string("Host"), ngx_string("$data_dome_http_host")},
    { ngx_string("Referer"), ngx_string("$data_dome_http_referer")},
    { ngx_string("Request"), ngx_string("$data_dome_request_uri")},
    { ngx_string("Protocol"), ngx_string("$scheme")},
    { ngx_string("Method"), ngx_string("$request_method")},
    { ngx_string("CookiesLen"), ngx_string("$data_dome_http_cookie_len")},
    { ngx_string("TimeRequest"), ngx_string("$data_dome_timestamp")},
    { ngx_string("ServerHostname"), ngx_string("$data_dome_http_host")},
    { ngx_string("RequestModuleName"), ngx_string("Nginx")},
    { ngx_string("ModuleVersion"), ngx_string("$data_dome_module_version")},
    { ngx_string("ServerName"), ngx_string("$hostname")},
    { ngx_string("XForwaredForIP"), ngx_string("$data_dome_http_x_forwarded_for")},
    { ngx_string("HeadersList"), ngx_string("$data_dome_headers_list")},
    { ngx_string("AuthorizationLen"), ngx_string("$data_dome_http_authorization_len")},
    { ngx_string("X-Requested-With"), ngx_string("$data_dome_http_x_requested_with")},
    { ngx_string("Origin"), ngx_string("$data_dome_http_origin")},
    { ngx_string("Connection"), ngx_string("$data_dome_http_connection")},
    { ngx_string("Pragma"), ngx_string("$data_dome_http_pragma")},
    { ngx_string("CacheControl"), ngx_string("$data_dome_http_cache_control")},
    { ngx_string("ContentType"), ngx_string("$data_dome_http_content_type")},
    { ngx_string("From"), ngx_string("$data_dome_http_from")},
    { ngx_string("X-Real-IP"), ngx_string("$data_dome_http_x_real_ip")},
    { ngx_string("Via"), ngx_string("$data_dome_http_via")},
    { ngx_string("TrueClientIP"), ngx_string("$data_dome_http_true_client_ip")},
    { ngx_string("PostParamLen"), ngx_string("$data_dome_post_param_len")},
    { ngx_string("Accept"), ngx_string("$data_dome_http_accept")},
    { ngx_string("AcceptCharset"), ngx_string("$data_dome_http_accept_charset")},
    { ngx_string("AcceptEncoding"), ngx_string("$data_dome_http_accept_encoding")},
    { ngx_string("AcceptLanguage"), ngx_string("$data_dome_http_accept_language")},
    { ngx_null_string, ngx_null_string }
};


static ngx_keyval_t ngx_http_data_dome_debug_params[] = {
    { ngx_null_string, ngx_null_string }
};


static ngx_int_t
ngx_http_data_dome_shield_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
  ngx_http_data_dome_shield_loc_conf_t *lcf;

  lcf = ngx_http_get_module_loc_conf(r, ngx_http_data_dome_shield_module);

  if (lcf->key.len == 0) {
    v->not_found = 1;
    return NGX_OK;
  }

  v->len = lcf->key.len;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->data = lcf->key.data;

  return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_shield_request_body_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
  size_t                        len, key_len;
  ngx_http_script_code_pt       code;
  ngx_http_script_engine_t      e, le;
  ngx_http_script_len_code_pt   lcode;

  ngx_http_data_dome_shield_loc_conf_t *lcf;

  lcf = ngx_http_get_module_loc_conf(r, ngx_http_data_dome_shield_module);

  ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

  ngx_http_script_flush_no_cacheable_variables(r, lcf->params.flushes);

  le.ip = lcf->params.lengths->elts;
  le.request = r;
  le.flushed = 1;

  len = 0;

  while (*(uintptr_t *) le.ip) {
    while (*(uintptr_t *) le.ip) {
      lcode = *(ngx_http_script_len_code_pt *) le.ip;
      len += lcode(&le);
    }
    le.ip += sizeof(uintptr_t);
  }

  if (len == 0) {
    v->not_found = 1;
    return NGX_OK;
  }


  v->data = ngx_palloc(r->pool, len * sizeof(u_char));
  if (v->data == NULL) {
    return NGX_ERROR;
  }

  v->len = len;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

  e.ip = lcf->params.values->elts;
  e.pos = v->data;
  e.request = r;
  e.flushed = 1;

  le.ip = lcf->params.lengths->elts;

  while (*(uintptr_t *) le.ip) {
    lcode = *(ngx_http_script_len_code_pt *) le.ip;

    key_len = lcode(&le);

    if (*(ngx_http_script_len_code_pt *) le.ip) {

      for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
	lcode = *(ngx_http_script_len_code_pt *) le.ip;
      }

      if (len <= 1) {
	v->len -= key_len;
	v->len -= len;
	e.skip = 1;
      } else {
	e.skip = 0;
      }

    } else {
      e.skip = 0;
    }

    le.ip += sizeof(uintptr_t);

    while (*(uintptr_t *) e.ip) {
      code = *(ngx_http_script_code_pt *) e.ip;
      code((ngx_http_script_engine_t *) &e);
    }
    e.ip += sizeof(uintptr_t);
  }

  if (v->len > MAX_PARAM_DATALEN) {
    v->len = MAX_PARAM_DATALEN;
  }

  return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_shield_timestamp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
  struct timeval   tv;

  v->valid = 0;
  v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);

  if (v->data == NULL) {
    return NGX_ERROR;
  }

  ngx_gettimeofday(&tv);

  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;


  v->len = ngx_sprintf(v->data, "%D%06uD", tv.tv_sec, tv.tv_usec) - v->data;

  return NGX_OK;
}

static ngx_http_data_dome_shield_ctx_t *
ngx_http_data_dome_shield_lookup_client_id(ngx_http_request_t *r)
{
  ngx_http_data_dome_shield_ctx_t      *ctx;
  ngx_http_data_dome_shield_loc_conf_t *lcf;

  ctx = ngx_http_get_module_ctx(r->main, ngx_http_data_dome_shield_module);
  if (ctx != NULL) {
    return ctx;
  }

  ctx = ngx_pcalloc(r->main->pool, sizeof(ngx_http_data_dome_shield_ctx_t));
  if (ctx == NULL) {
    return NULL;
  }

  lcf = ngx_http_get_module_loc_conf(r, ngx_http_data_dome_shield_module);
  ngx_http_parse_multi_header_lines(&r->main->headers_in.cookies, &lcf->cookie,
					&ctx->client_id);

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
		 "Data Dome Shield use cliend id cookie: name: %v, client_id: %V",
		 &lcf->cookie, &ctx->client_id);

  ngx_http_set_ctx(r->main, ctx, ngx_http_data_dome_shield_module);

  return ctx;
}


char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

u_char *url_encode_start(u_char *str, ssize_t value_len, ssize_t limit) {
  do {
    str--;
    value_len--;
    limit--;
    if (!isalnum(*str) && *str != '-' && *str != '_' && *str != '.' && *str != '~' && *str != ' ') {
      limit -= 2;
    }
  } while (value_len > 0 && limit > 0);

  return str;
}

ssize_t url_encode(const unsigned char *str, char unsigned *buf, ssize_t value_len, ssize_t limit) {
  const unsigned char *pstr = str;
  unsigned char *pbuf = buf;

  while (value_len && *pstr && limit) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
      *pbuf++ = *pstr;
      limit--;
    } else if (*pstr == ' ') {
      *pbuf++ = '+';
      limit--;
    } else {
      if (limit < 3) {
        break;
      }
      *pbuf++ = '%';
      *pbuf++ = to_hex(*pstr >> 4);
      *pbuf++ = to_hex(*pstr & 15);
      limit -= 3;
    }
    pstr++;
    if (value_len > 0) {
      value_len--;
    }
  }

  return pbuf-buf;
}


static ngx_int_t ngx_http_data_dome_shield_url_encode_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, int limit, int from_end)
{
    u_char *old_data = v->data;
    size_t  old_len  = v->len;

    if (!v->valid || v->not_found) {
        return NGX_OK;
    }

    v->len = v->len * 3;
    v->data = ngx_palloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    if (from_end) {
        u_char* old_end = old_data + old_len;

        old_data = url_encode_start(old_end, old_len, limit);
        old_len = old_end - old_data;
    }


    v->len = url_encode(old_data, v->data, old_len, limit);

    return NGX_OK;
}


static ngx_int_t ngx_http_data_dome_shield_client_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
  ngx_http_data_dome_shield_ctx_t      *ctx;

  ctx = ngx_http_data_dome_shield_lookup_client_id(r);
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  if (ctx->client_id.len == 0) {
      v->not_found = 1;

      return NGX_OK;
  }


  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->len = ctx->client_id.len;
  v->data = ctx->client_id.data;

  return ngx_http_data_dome_shield_url_encode_variable(r, v, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_request(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data, int limit)
{
    ngx_str_t  *s;

    s = (ngx_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;
    } else {
        v->not_found = 1;
    }

    return ngx_http_data_dome_shield_url_encode_variable(r, v, limit, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_request_2048(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    return ngx_http_data_dome_shield_http_variable_request(r, v, data, 2048);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_header(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data, int limit)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) r->main + data);

    if (h) {
        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;
    } else {
        v->not_found = 1;
    }

    return ngx_http_data_dome_shield_url_encode_variable(r, v, limit, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_header_1024(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    return ngx_http_data_dome_shield_http_variable_header(r, v, data, 1024);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_header_768(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    return ngx_http_data_dome_shield_http_variable_header(r, v, data, 768);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_header_512(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    return ngx_http_data_dome_shield_http_variable_header(r, v, data, 512);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_unknown_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part, int limit, int from_end)
{
    ngx_int_t rc = ngx_http_variable_unknown_header(v, var, part, 0);

    if (rc == NGX_OK && v->valid && !v->not_found) {
        return ngx_http_data_dome_shield_url_encode_variable(r, v, limit, from_end);
    }

    return rc;
}

static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_x_forwarded_for(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("x_forwarded_for");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 512, 1);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_accept(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("accept");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 512, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_accept_charset(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("accept_charset");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_accept_encoding(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("accept_encoding");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_accept_language(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("accept_language");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 256, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_x_requested_with(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("x_requested_with");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_origin(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("origin");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 512, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_connection(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("connection");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_pragma(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("pragma");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_cache_control(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("cache_control");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_content_type(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("content_type");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}

static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_from(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("from");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_x_real_ip(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("x_real_ip");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_via(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("via");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 256, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_http_true_client_ip(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("true_client_ip");

    return ngx_http_data_dome_shield_http_variable_unknown_header(r, v, &var, &r->main->headers_in.headers.part, 128, 0);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v)
{
    size_t  len;

    if (v->not_found) {
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->len = sizeof("0") - 1;
        v->data = (u_char *) "0";
        return NGX_OK;
    }

    len = v->len;

    v->len = sizeof("2147483647") - 1;
    v->data = ngx_palloc(r->pool, v->len);
    if (v->data == NULL) {
        v->valid = 0;
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%d", len) - v->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_header_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part)
{
    ngx_int_t rc = ngx_http_variable_unknown_header(v, var, part, 0);

    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_data_dome_shield_http_variable_length(r, v);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_cookies_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("cookie");

    return ngx_http_data_dome_shield_http_variable_header_length(r, v, &var, &r->main->headers_in.headers.part);
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_authorization_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t var = ngx_string("authorization");

    return ngx_http_data_dome_shield_http_variable_header_length(r, v, &var, &r->main->headers_in.headers.part);
}

static ngx_int_t
ngx_http_data_dome_shield_http_variable_post_param_len(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof("2147483647") - 1;
    v->data = ngx_palloc(r->pool, v->len);
    if (v->data == NULL) {
        v->valid = 0;
        return NGX_ERROR;
    }

    if (r->chunked) {
        v->len = sizeof("-1") - 1;
        v->data = (u_char *) "-1";
    } else {
        v->len = ngx_sprintf(v->data, "%d", r->main->headers_in.content_length_n) - v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_shield_http_variable_headers_list(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                          *p;
    ngx_uint_t                       i, j;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *header;

    v->len = 0;

    part = &r->main->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (v->len > 0) {
            v->len += sizeof(",") - 1;
        }

        v->len += header[i].key.len;
    }

    if (v->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_palloc(r->pool, v->len);
    if (v->data == NULL) {
        v->valid = 0;
        return NGX_ERROR;
    }

    p = v->data;

    part = &r->main->headers_in.headers.part;
    header = part->elts;

    v->len = 0;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (v->len > 0) {
            v->len += sizeof(",") - 1;
            *p = ',';
            p++;
        }

        for (j = 0; j < header[i].key.len; j++) {
            *p = ngx_tolower(header[i].key.data[j]);
            p++;
        }

        v->len += header[i].key.len;
    }

    return ngx_http_data_dome_shield_url_encode_variable(r, v, 512, 0);
}

static ngx_int_t
ngx_http_data_dome_shield_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_data_dome_shield_vars; v->name.len; v++) {
	var = ngx_http_add_variable(cf, &v->name, v->flags);
	if (var == NULL) {
	    return NGX_ERROR;
	}

	var->get_handler = v->get_handler;
	var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_data_dome_shield_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_data_dome_shield_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_data_dome_shield_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  /*
   * set by ngx_pcalloc():
   *
   *     conf->key = { 0, NULL };
   *     conf->cookie = { 0, NULL };
   */

  conf->debug_params = NGX_CONF_UNSET;

  return conf;
}


static char *
ngx_http_data_dome_shield_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_data_dome_shield_loc_conf_t  *prev = parent;
  ngx_http_data_dome_shield_loc_conf_t  *conf = child;

  ngx_int_t    rc;

  ngx_conf_merge_str_value(conf->key, prev->key, "");

  ngx_conf_merge_str_value(conf->cookie, prev->cookie, "datadome");

  ngx_conf_merge_value(conf->debug_params, prev->debug_params, 0);

  rc = ngx_http_data_dome_shield_init_params(cf, conf, &conf->params,
					     ngx_http_data_dome_params,
					     conf->debug_params ? ngx_http_data_dome_debug_params : NULL);
  if (rc != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_data_dome_shield_init_params(ngx_conf_t *cf, ngx_http_data_dome_shield_loc_conf_t *conf,
    ngx_http_data_dome_shield_params_t *params, ngx_keyval_t *default_params, ngx_keyval_t *debug_params)
{
  u_char                       *p;
  size_t                        size;
  uintptr_t                    *code;
  ngx_uint_t                    i;
  ngx_array_t                   params_merged;
  ngx_keyval_t                 *src, *s, *h;
  ngx_http_script_compile_t     sc;
  ngx_http_script_copy_code_t  *copy;

  if (ngx_array_init(&params_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
      != NGX_OK)
    {
      return NGX_ERROR;
    }

  if (conf->params_source == NULL) {
    conf->params_source = ngx_array_create(cf->pool, 4,
					   sizeof(ngx_keyval_t));
    if (conf->params_source == NULL) {
      return NGX_ERROR;
    }
  }

  params->lengths = ngx_array_create(cf->pool, 64, 1);
  if (params->lengths == NULL) {
    return NGX_ERROR;
  }

  params->values = ngx_array_create(cf->pool, 512, 1);
  if (params->values == NULL) {
    return NGX_ERROR;
  }

  src = conf->params_source->elts;
  for (i = 0; i < conf->params_source->nelts; i++) {

    s = ngx_array_push(&params_merged);
    if (s == NULL) {
      return NGX_ERROR;
    }

    *s = src[i];
  }

  h = default_params;

merge_default_params:
  while (h->key.len) {

    src = params_merged.elts;
    for (i = 0; i < params_merged.nelts; i++) {
      if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
	goto next;
      }
    }

    s = ngx_array_push(&params_merged);
    if (s == NULL) {
      return NGX_ERROR;
    }

    *s = *h;

  next:

    h++;
  }

  if (debug_params) {
    h = debug_params;
    debug_params = NULL;
    goto merge_default_params;
  }

  src = params_merged.elts;
  for (i = 0; i < params_merged.nelts; i++) {

    if (src[i].value.len == 0) {
      continue;
    }

    if (ngx_http_script_variables_count(&src[i].value) == 0) {
      copy = ngx_array_push_n(params->lengths,
			      sizeof(ngx_http_script_copy_code_t));
      if (copy == NULL) {
	return NGX_ERROR;
      }

      copy->code = (ngx_http_script_code_pt)ngx_http_script_copy_len_code;
      copy->len = src[i].key.len + sizeof("=") - 1 + src[i].value.len + sizeof("&") - 1;


      size = (sizeof(ngx_http_script_copy_code_t)
	      + src[i].key.len + sizeof("=") - 1
	      + src[i].value.len + sizeof("&") - 1
	      + sizeof(uintptr_t) - 1)
	& ~(sizeof(uintptr_t) - 1);

      copy = ngx_array_push_n(params->values, size);
      if (copy == NULL) {
	return NGX_ERROR;
      }

      copy->code = ngx_http_script_copy_code;
      copy->len = src[i].key.len + sizeof("=") - 1 + src[i].value.len + sizeof("&") - 1;

      p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);

      p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
      *p++ = '=';
      p = ngx_cpymem(p, src[i].value.data, src[i].value.len);
      *p++ = '&';

    } else {
      copy = ngx_array_push_n(params->lengths,
			      sizeof(ngx_http_script_copy_code_t));
      if (copy == NULL) {
	return NGX_ERROR;
      }

      copy->code = (ngx_http_script_code_pt)ngx_http_script_copy_len_code;
      copy->len = src[i].key.len + sizeof("=") - 1;


      size = (sizeof(ngx_http_script_copy_code_t)
	      + src[i].key.len + sizeof("=") - 1 + sizeof(uintptr_t) - 1)
	& ~(sizeof(uintptr_t) - 1);

      copy = ngx_array_push_n(params->values, size);
      if (copy == NULL) {
	return NGX_ERROR;
      }

      copy->code = ngx_http_script_copy_code;
      copy->len = src[i].key.len + sizeof("=") - 1;

      p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
      p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
      *p++ = '=';

      ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

      sc.cf = cf;
      sc.source = &src[i].value;
      sc.flushes = &params->flushes;
      sc.lengths = &params->lengths;
      sc.values = &params->values;

      if (ngx_http_script_compile(&sc) != NGX_OK) {
	return NGX_ERROR;
      }

      copy = ngx_array_push_n(params->lengths,
			      sizeof(ngx_http_script_copy_code_t));
      if (copy == NULL) {
	return NGX_ERROR;
      }

      copy->code = (ngx_http_script_code_pt)ngx_http_script_copy_len_code;
      copy->len = sizeof("&") - 1;


      size = (sizeof(ngx_http_script_copy_code_t)
	      + sizeof("&") - 1 + sizeof(uintptr_t) - 1)
	& ~(sizeof(uintptr_t) - 1);

      copy = ngx_array_push_n(params->values, size);
      if (copy == NULL) {
	return NGX_ERROR;
      }

      copy->code = ngx_http_script_copy_code;
      copy->len = sizeof("&") - 1;

      p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
      *p++ = '&';
    }

    code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
    if (code == NULL) {
      return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    code = ngx_array_push_n(params->values, sizeof(uintptr_t));
    if (code == NULL) {
      return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;
  }

  code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
  if (code == NULL) {
    return NGX_ERROR;
  }

  *code = (uintptr_t) NULL;

  return NGX_OK;
}
