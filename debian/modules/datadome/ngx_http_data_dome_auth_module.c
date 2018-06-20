#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define MODULE_VERSION "2.34"


typedef struct {
    ngx_array_t              *uri_lengths;
    ngx_array_t              *uri_values;
    ngx_uint_t                learning;
    ngx_flag_t                pass_internal_redirect;
#if (NGX_PCRE)
    ngx_regex_t               *uri_regex;
    ngx_str_t                  uri_regex_raw;

    ngx_regex_t               *uri_regex_exclusion;
    ngx_str_t                  uri_regex_exclusion_raw;
#endif
    ngx_array_t               *vars;
} ngx_http_data_dome_auth_conf_t;


typedef struct {
    ngx_str_t                 uri;
    ngx_uint_t                processing;
    ngx_uint_t                done;
    ngx_uint_t                declined;
    ngx_int_t                 subrequest_rc;
    ngx_http_request_t       *subrequest;

    ngx_http_event_handler_pt     read_event_handler;
    ngx_http_event_handler_pt     write_event_handler;
} ngx_http_data_dome_auth_ctx_t;


typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_http_data_dome_auth_variable_t;


static ngx_int_t ngx_http_data_dome_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_data_dome_subrequest(ngx_http_request_t *r);
static ngx_int_t ngx_http_data_dome_auth_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static ngx_int_t ngx_http_data_dome_auth_set_variables(ngx_http_request_t *r,
    ngx_http_data_dome_auth_conf_t *acf, ngx_http_data_dome_auth_ctx_t *ctx);
static ngx_int_t ngx_http_data_dome_auth_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_data_dome_auth_create_conf(ngx_conf_t *cf);
static char *ngx_http_data_dome_auth_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_data_dome_auth_init(ngx_conf_t *cf);
static char *ngx_http_data_dome_auth(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_data_dome_auth_uri_regex(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_data_dome_auth_uri_regex_exclusion(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_data_dome_auth_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_data_dome_auth_is_uri_regex_matched(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_auth_module_version(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_data_dome_auth_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_data_dome_auth_commands[] = {

    { ngx_string("data_dome_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_data_dome_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("data_dome_auth_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_data_dome_auth_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("data_dome_auth_uri_regex"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_data_dome_auth_uri_regex,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("data_dome_auth_uri_regex_exclusion"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_data_dome_auth_uri_regex_exclusion,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("data_dome_auth_pass_internal_redirect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_data_dome_auth_conf_t, pass_internal_redirect),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_data_dome_auth_module_ctx = {
    ngx_http_data_dome_auth_add_variables, /* preconfiguration */
    ngx_http_data_dome_auth_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_data_dome_auth_create_conf,   /* create location configuration */
    ngx_http_data_dome_auth_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_data_dome_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_data_dome_auth_module_ctx,   /* module context */
    ngx_http_data_dome_auth_commands,      /* module directives */
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


static ngx_http_variable_t  ngx_http_data_dome_auth_vars[] = {

  { ngx_string("data_dome_auth_is_uri_regex_matched"), NULL,
    ngx_http_data_dome_auth_is_uri_regex_matched, 0,
    NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

  { ngx_string("data_dome_module_version"), NULL,
    ngx_http_data_dome_auth_module_version, 0,
    NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

  { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_data_dome_auth_is_uri_regex_matched(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_data_dome_auth_conf_t  *acf;

    acf = ngx_http_get_module_loc_conf(r, ngx_http_data_dome_auth_module);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (acf->uri_regex_exclusion) {
        if (ngx_regex_exec(acf->uri_regex_exclusion, &r->main->uri, NULL, 0) != NGX_REGEX_NO_MATCHED) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
                           "Data Dome auth is uri regex exclusion matched; r->main->uri: %V, acf->uri_regex_exclusion: %V",
                           &r->main->uri, &acf->uri_regex_exclusion_raw);
            v->len = sizeof("0") - 1;
            v->data = (u_char *) "0";
            return NGX_OK;
        }
    }

    if (acf->uri_regex) {
        if (ngx_regex_exec(acf->uri_regex, &r->main->uri, NULL, 0) == NGX_REGEX_NO_MATCHED) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
                           "Data Dome auth is uri regex matched var: uri isn't matched; r->main->uri: %V, acf->uri_regex: %V",
                           &r->main->uri, &acf->uri_regex_raw);
            v->len = sizeof("0") - 1;
            v->data = (u_char *) "0";
            return NGX_OK;
        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
                           "Data Dome auth is uri regex matched var: uri is matched; r->main->uri: %V, acf->uri_regex: %V",
                           &r->main->uri, &acf->uri_regex_raw);
            v->len = sizeof("1") - 1;
            v->data = (u_char *) "1";
            return NGX_OK;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
                   "Data Dome auth uri regex uri isn't set");
    v->len = sizeof("1") - 1;
    v->data = (u_char *) "1";
    return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_auth_module_version(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = sizeof(MODULE_VERSION) - 1;
    v->data = (u_char *) MODULE_VERSION;

    return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_auth_execute_x_datadome_headers(ngx_pool_t *pool, const char* x_datadome_header, ngx_list_t *src, ngx_list_t *dst)
{
  u_char           *end;
  ngx_str_t         x_datadome_headers;
  ngx_uint_t        i, j;
  ngx_list_part_t  *part, *sub_part;
  ngx_table_elt_t  *header, *sub_header, *new_header;

  ngx_uint_t x_datadome_header_len = strlen(x_datadome_header);

  part = &src->part;
  header = part->elts;

  x_datadome_headers.len = 0;
  x_datadome_headers.data = NULL;

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

    if (header[i].key.len != x_datadome_header_len) {
      continue;
    }

    if (ngx_strncmp(header[i].key.data, x_datadome_header, header[i].key.len) != 0) {
      continue;
    }

    x_datadome_headers.len = header[i].value.len;
    x_datadome_headers.data = ngx_pcalloc(pool, x_datadome_headers.len + 1);
    if (x_datadome_headers.data == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpymem(x_datadome_headers.data, header[i].value.data, x_datadome_headers.len);

    break;
  }

  while (x_datadome_headers.len > 0) {

      end = (u_char *) ngx_strstr(x_datadome_headers.data, " ");
      if (end == NULL) {
        end = x_datadome_headers.data + x_datadome_headers.len;
      }

      part = &src->part;
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

        if (header[i].key.len != (size_t) (end - x_datadome_headers.data)) {
          continue;
        }

        if (ngx_strncmp(header[i].key.data, x_datadome_headers.data, header[i].key.len) != 0) {
          continue;
        }

        sub_part = &dst->part;
        sub_header = sub_part->elts;

        new_header = NULL;

        for (j = 0; /* void */ ; j++) {
            if (j >= sub_part->nelts) {
                if (sub_part->next == NULL) {
                    break;
                }

                sub_part = sub_part->next;
                sub_header = sub_part->elts;
                j = 0;
            }

            if (sub_header[j].hash == 0) {
              continue;
            }

            if (sub_header[j].key.len != header[i].key.len) {
              continue;
            }

            if (ngx_strncmp(sub_header[j].key.data, header[i].key.data, sub_header[j].key.len) != 0) {
              continue;
            }

            if (sub_header[j].key.len == sizeof("Set-Cookie") - 1 &&
                ngx_strncmp(sub_header[j].key.data, "Set-Cookie", sub_header[j].key.len) == 0) {
                break;
            }

            new_header = &sub_header[j];
            break;
        }

        if (new_header == NULL) {
            new_header = ngx_list_push(dst);
            if (new_header == NULL) {
                return NGX_ERROR;
            }
        }

        new_header->hash = 1;
        new_header->key = header[i].key;
        new_header->value = header[i].value;
        new_header->lowcase_key = header[i].lowcase_key;

        break;
      }

      x_datadome_headers.len -= end - x_datadome_headers.data;
      x_datadome_headers.data = end;
      while (*x_datadome_headers.data == ' ') {
        x_datadome_headers.data++;
        x_datadome_headers.len--;
      }

  }

  return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_auth_handler(ngx_http_request_t *r)
{
    ngx_buf_t                       *b;
    ngx_int_t                        rc;
    ngx_str_t                        val;
    ngx_str_t                        x_datadome_response;
    ngx_uint_t                       i;
    ngx_chain_t                      out;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *header;
    ngx_table_elt_t                 *location;
    ngx_http_data_dome_auth_ctx_t   *ctx;
    ngx_http_data_dome_auth_conf_t  *acf;

    // you can dissable this module in location or if level
    acf = ngx_http_get_module_loc_conf(r, ngx_http_data_dome_auth_module);

    if (acf->uri_lengths == NULL) {
  return NGX_DECLINED;
    }

    if (r->internal && acf->pass_internal_redirect) {
  return NGX_DECLINED;
    }

    // but module use main request context to keep the status
    // to prevent duplicated query to API server
    ctx = ngx_http_get_module_ctx(r->main, ngx_http_data_dome_auth_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
		   "Data Dome auth request handler, ctx: %p", ctx);

    if (ctx != NULL) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
		   "Data Dome auth request handler ctx: declined %d, processing: %d, done: %d",
		    ctx->declined, ctx->processing, ctx->done);

	if (ctx->declined) {
	    return NGX_DECLINED;
	}

	if (ctx->processing) {
	    return NGX_OK;
	}

	if (!ctx->done) {
	    return NGX_AGAIN;
	}

    if (ngx_http_data_dome_auth_set_variables(r, acf, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

	if (acf->learning) {
	    return NGX_OK;
	}

    if (ctx->subrequest_rc < NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    x_datadome_response.len = 0;

    part = &ctx->subrequest->headers_out.headers.part;
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

        if (header[i].key.len != sizeof("X-DataDomeResponse") - 1) {
            continue;
        }

        if (ngx_strncmp(header[i].key.data, "X-DataDomeResponse", header[i].key.len) != 0) {
            continue;
        }

        x_datadome_response = header[i].value;

        break;
    }

    if (x_datadome_response.len == 0) {
	    ngx_log_error(NGX_LOG_ERR, r->main->connection->log, 0, "API server response hasn't got X-DataDomeResponse");
	    return NGX_DECLINED;
    }

    if ((ngx_uint_t)ngx_atoi(x_datadome_response.data, x_datadome_response.len) != ctx->subrequest->headers_out.status) {
	    ngx_log_error(NGX_LOG_ERR, r->main->connection->log, 0, "API server response's X-DataDomeResponse (%V) != status (%d)",
	        &x_datadome_response, ctx->subrequest->headers_out.status);
	    return NGX_DECLINED;
    }

	if (ngx_http_data_dome_auth_execute_x_datadome_headers(r->main->pool, "X-DataDome-headers",
	                                                       &ctx->subrequest->headers_out.headers,
	                                                       &r->main->headers_out.headers) == NGX_ERROR) {
	    return NGX_ERROR;
	}

	if (ngx_http_data_dome_auth_execute_x_datadome_headers(r->main->pool, "X-DataDome-request-headers",
	                                                       &ctx->subrequest->headers_out.headers,
	                                                       &r->main->headers_in.headers) == NGX_ERROR) {
	    return NGX_ERROR;
	}

	switch (ctx->subrequest->headers_out.status) {
	case NGX_HTTP_MOVED_PERMANENTLY:
	case NGX_HTTP_MOVED_TEMPORARILY:
	case NGX_HTTP_UNAUTHORIZED:
	case NGX_HTTP_FORBIDDEN:

        part = &ctx->subrequest->headers_out.headers.part;
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

            if (header[i].key.len != sizeof("Location") - 1) {
                continue;
            }

            if (ngx_strncmp(header[i].key.data, "Location", header[i].key.len) != 0) {
                continue;
            }

            location = ngx_list_push(&r->main->headers_out.headers);
            if (location == NULL) {
              return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            location->hash = 1;
            location->key = header[i].key;
            location->lowcase_key = header[i].lowcase_key;
            location->value = header[i].value;

            break;
        }

	    // nginx reset upstream buffer length, so, use body lenght from header ;)
	    val.len = ctx->subrequest->headers_out.content_length_n;
	    val.data = ctx->subrequest->upstream->buffer.pos;

	    // if response hasn't Content-Length and body the length was -1, fix it
	    if (ctx->subrequest->headers_out.content_length_n < 0) {
	      val.len = 0;
	    }

	    if (val.len == 0) {
    	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	    		   "Data Dome auth send response without body: s: %d",
		    	   ctx->subrequest->headers_out.status);
            return ctx->subrequest->headers_out.status;
	    }

	    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			   "Data Dome auth send response: s: %d, c: %V, b: %V",
			   ctx->subrequest->headers_out.status, &ctx->subrequest->headers_out.content_type, &val);

        r->headers_out.status = ctx->subrequest->headers_out.status;

        r->headers_out.content_length_n = val.len;

        if (ctx->subrequest->headers_out.content_type.len) {
            r->headers_out.content_type_len = ctx->subrequest->headers_out.content_type.len;
            r->headers_out.content_type = ctx->subrequest->headers_out.content_type;
        } else {
            if (ngx_http_set_content_type(r) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (r->method == NGX_HTTP_HEAD || val.len == 0) {
            rc = ngx_http_send_header(r);
            if (rc != NGX_OK) {
                return rc;
            }

            return NGX_DONE;
        }

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b->pos = val.data;
        b->last = val.data + val.len;
        b->memory = val.len ? 1 : 0;
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        out.buf = b;
        out.next = NULL;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK) {
            return rc;
        }

        if (r->header_only) {
            ngx_http_finalize_request(r, NGX_DONE);
            return NGX_DONE;
        }

        rc = ngx_http_output_filter(r, &out);
	    if (rc != NGX_OK) {
	      return rc;
	    }

        ngx_http_finalize_request(r, NGX_DONE);
	    return NGX_DONE;

	case NGX_HTTP_OK:

	    return NGX_OK;

	default:

	    ngx_log_error(NGX_LOG_ERR, r->main->connection->log, 0,
			  "Data Dome auth request unexpected status: %d, pass", ctx->subrequest->headers_out.status);

	    return NGX_OK;
	}
    }

    ctx = ngx_pcalloc(r->main->pool, sizeof(ngx_http_data_dome_auth_ctx_t));
    if (ctx == NULL) {
	return NGX_ERROR;
    }

    if (ngx_http_script_run(r, &ctx->uri, acf->uri_lengths->elts, 0, acf->uri_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (ngx_strncmp(ctx->uri.data, "off", ctx->uri.len) == 0) {
	    return NGX_DECLINED;
    }

    ngx_http_set_ctx(r->main, ctx, ngx_http_data_dome_auth_module);

#if (NGX_PCRE)

    if (acf->uri_regex_exclusion) {
        if (ngx_regex_exec(acf->uri_regex_exclusion, &r->main->uri, NULL, 0) != NGX_REGEX_NO_MATCHED) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
                  "Data Dome auth URI regex exclusion: \"%V\" match with URI: %V",
                   &acf->uri_regex_exclusion_raw, &r->main->uri);

            ctx->declined = 1;
            return NGX_DECLINED;
        }
    }

    if (acf->uri_regex) {

	if (ngx_regex_exec(acf->uri_regex, &r->main->uri, NULL, 0) != NGX_REGEX_NO_MATCHED) {

	    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->main->connection->log, 0,
			  "Data Dome auth URI regex: \"%V\" match with URI: %V",
			   &acf->uri_regex_raw, &r->main->uri);

	    goto validate;
	}

	ctx->declined = 1;
	return NGX_DECLINED;
    }

 validate:

#endif

    ctx->processing = 1;

    // keep original read and write event handler because read client body may override it
    ctx->read_event_handler = r->main->read_event_handler;
    ctx->write_event_handler = r->main->write_event_handler;

    return ngx_http_data_dome_subrequest(r);
}

static ngx_int_t
ngx_http_data_dome_subrequest(ngx_http_request_t *r)
{
    ngx_http_request_t              *sr;
    ngx_http_post_subrequest_t      *ps;
    ngx_http_data_dome_auth_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_data_dome_auth_module);

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
	return NGX_ERROR;
    }

    ps->handler = ngx_http_data_dome_auth_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &ctx->uri, NULL, &sr, ps,
			    NGX_HTTP_SUBREQUEST_WAITED
			  | NGX_HTTP_SUBREQUEST_IN_MEMORY)
	!= NGX_OK)
    {
	return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
	return NGX_ERROR;
    }

    /*
     * cleanup headers_in to avoid attempts to send it to the API server
     */

    ngx_memzero(&sr->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    if (ngx_list_init(&sr->headers_in.headers, r->pool, 2, sizeof(ngx_table_elt_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->subrequest = sr;

    return NGX_AGAIN;
}



static ngx_int_t
ngx_http_data_dome_auth_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_data_dome_auth_ctx_t   *ctx = data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		   "Data Dome auth request done s:%d, rc: %d", r->headers_out.status, rc);

    // restore original read and write event handler
    r->main->read_event_handler = ctx->read_event_handler;
    r->main->write_event_handler = ctx->write_event_handler;

    ctx->done = 1;
    ctx->processing = 0;
    ctx->subrequest_rc = rc;

    return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_auth_set_variables(ngx_http_request_t *r,
    ngx_http_data_dome_auth_conf_t *acf, ngx_http_data_dome_auth_ctx_t *ctx)
{
    ngx_str_t                          val;
    ngx_http_variable_t               *v;
    ngx_http_variable_value_t         *vv;
    ngx_http_data_dome_auth_variable_t  *av, *last;
    ngx_http_core_main_conf_t         *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Data Dome auth request set variables");

    if (acf->vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    av = acf->vars->elts;
    last = av + acf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_data_dome_auth_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Data Dome auth request variable");

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_data_dome_auth_create_conf(ngx_conf_t *cf)
{
    ngx_http_data_dome_auth_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_data_dome_auth_conf_t));
    if (conf == NULL) {
	return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->learning = NGX_CONF_UNSET_UINT;
	conf->pass_internal_redirect = NGX_CONF_UNSET;
    conf->vars = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_data_dome_auth_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_data_dome_auth_conf_t *prev = parent;
    ngx_http_data_dome_auth_conf_t *conf = child;

#if (NGX_PCRE)
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
#endif

    if (conf->uri_lengths == NULL) {
        conf->uri_lengths = prev->uri_lengths;
        conf->uri_values = prev->uri_values;
    }
    ngx_conf_merge_uint_value(conf->learning, prev->learning, 0);
	ngx_conf_merge_value(conf->pass_internal_redirect, prev->pass_internal_redirect, 1);

#if (NGX_PCRE)
    if (conf->uri_regex == NULL) {
    conf->uri_regex = prev->uri_regex;
	conf->uri_regex_raw = prev->uri_regex_raw;

	if (conf->uri_regex == NULL) {
	    ngx_str_set(&conf->uri_regex_raw, "");

	}
    }

        if (conf->uri_regex_exclusion == NULL) {
  conf->uri_regex_exclusion = prev->uri_regex_exclusion;
	conf->uri_regex_exclusion_raw = prev->uri_regex_exclusion_raw;

	if (conf->uri_regex_exclusion == NULL) {
	    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

	    ngx_str_set(&rc.pattern, "\\.(js|css|jpg|jpeg|png|ico|gif|tiff|svg|woff|woff2|ttf|eot|mp4|otf)$");
	    rc.pool = cf->pool;
	    rc.options = NGX_REGEX_CASELESS;
	    rc.err.len = NGX_MAX_CONF_ERRSTR;
	    rc.err.data = errstr;

	    if (ngx_regex_compile(&rc) != NGX_OK) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
		return NGX_CONF_ERROR;
	    }

	    conf->uri_regex_exclusion = rc.regex;
	    conf->uri_regex_exclusion_raw = rc.pattern;
	}
    }
#endif

    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_data_dome_auth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
	return NGX_ERROR;
    }

    *h = ngx_http_data_dome_auth_handler;

    return NGX_OK;
}


static char *
ngx_http_data_dome_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_data_dome_auth_conf_t *acf = conf;

    ngx_str_t        *value;
    ngx_str_t         uri;
    ngx_uint_t        n;

    ngx_http_script_compile_t   sc;

    if (acf->uri_lengths != NULL) {
	return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "learning") && cf->args->nelts == 3) {
	acf->learning = 1;
	uri = value[2];
    } else {
	uri = value[1];
    }

    n = ngx_http_script_variables_count(&uri);

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &uri;
    sc.lengths = &acf->uri_lengths;
    sc.values = &acf->uri_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_data_dome_auth_uri_regex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_PCRE)
    ngx_http_data_dome_auth_conf_t *acf = conf;

    ngx_str_t            *value;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.options = NGX_REGEX_CASELESS;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
	return NGX_CONF_ERROR;
    }

    acf->uri_regex = rc.regex;
    acf->uri_regex_raw = value[1];

    return NGX_CONF_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "\"%V\" requires PCRE library", &cmd->name);
    return NGX_CONF_ERROR;

#endif
}

static char *
ngx_http_data_dome_auth_uri_regex_exclusion(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_PCRE)
    ngx_http_data_dome_auth_conf_t *acf = conf;

    ngx_str_t            *value;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.options = NGX_REGEX_CASELESS;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
	return NGX_CONF_ERROR;
    }

    acf->uri_regex_exclusion = rc.regex;
    acf->uri_regex_exclusion_raw = value[1];

    return NGX_CONF_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "\"%V\" requires PCRE library", &cmd->name);
    return NGX_CONF_ERROR;

#endif
}

static ngx_int_t
ngx_http_data_dome_auth_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_data_dome_auth_vars; v->name.len; v++) {
	var = ngx_http_add_variable(cf, &v->name, v->flags);
	if (var == NULL) {
	    return NGX_ERROR;
	}

	var->get_handler = v->get_handler;
	var->data = v->data;
    }

    return NGX_OK;
}

static char *
ngx_http_data_dome_auth_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_data_dome_auth_conf_t *acf = conf;

    ngx_str_t                         *value;
    ngx_http_variable_t               *v;
    ngx_http_data_dome_auth_variable_t  *av;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (acf->vars == NGX_CONF_UNSET_PTR) {
        acf->vars = ngx_array_create(cf->pool, 1, sizeof(ngx_http_data_dome_auth_variable_t));
        if (acf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    av = ngx_array_push(acf->vars);
    if (av == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    av->index = ngx_http_get_variable_index(cf, &value[1]);
    if (av->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_http_data_dome_auth_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
