/* mod_authz_webid
 * WebID authorization module for Apache 2
 *
 * Joe Presbrey <presbrey@csail.mit.edu>
 *
 * $Id: mod_authz_webid.c 29592 2010-09-03 20:13:33Z presbrey $
 */

#include "apr_strings.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include <redland.h>

#define URI__NS_ACL     "<http://www.w3.org/ns/auth/acl#>"
#define URI__NS_RDF     "<http://www.w3.org/1999/02/22-rdf-syntax-ns#>"
#define URI__FOAF_AGENT "<http://xmlns.com/foaf/0.1/Agent>"

#define WEBID_ACL_FNAME         ".meta.n3"
#define WEBID_ACCESS_INVALID    0
#define WEBID_ACCESS_READ       0x1
#define WEBID_ACCESS_WRITE      0x2
#define WEBID_ACCESS_CONTROL    0x4

#define WEBID_M_READ \
    (AP_METHOD_BIT << M_GET | \
     AP_METHOD_BIT << M_POST | \
     AP_METHOD_BIT << M_CONNECT | \
     AP_METHOD_BIT << M_OPTIONS | \
     AP_METHOD_BIT << M_TRACE | \
     AP_METHOD_BIT << M_PROPFIND)

#define WEBID_M_WRITE \
    (AP_METHOD_BIT << M_PUT | \
     AP_METHOD_BIT << M_DELETE | \
     AP_METHOD_BIT << M_PATCH | \
     AP_METHOD_BIT << M_PROPPATCH | \
     AP_METHOD_BIT << M_MKCOL | \
     AP_METHOD_BIT << M_COPY | \
     AP_METHOD_BIT << M_MOVE | \
     AP_METHOD_BIT << M_LOCK | \
     AP_METHOD_BIT << M_UNLOCK | \
     AP_METHOD_BIT << M_VERSION_CONTROL | \
     AP_METHOD_BIT << M_CHECKOUT | \
     AP_METHOD_BIT << M_UNCHECKOUT | \
     AP_METHOD_BIT << M_CHECKIN | \
     AP_METHOD_BIT << M_UPDATE | \
     AP_METHOD_BIT << M_LABEL | \
     AP_METHOD_BIT << M_REPORT | \
     AP_METHOD_BIT << M_MKWORKSPACE | \
     AP_METHOD_BIT << M_MKACTIVITY | \
     AP_METHOD_BIT << M_BASELINE_CONTROL | \
     AP_METHOD_BIT << M_MERGE)

#define SPARQL_URI_MODE_AGENT \
    " PREFIX rdf: " URI__NS_RDF \
    " PREFIX acl: " URI__NS_ACL \
    " SELECT ?rule WHERE {" \
    " ?rule rdf:type acl:Authorization ;" \
          " acl:%s <%s> ;" \
          " acl:mode acl:%s ;" \
          " acl:agent <%s> ." \
    " }"

#define SPARQL_URI_MODE_AGENTCLASS \
    " PREFIX rdf: " URI__NS_RDF \
    " PREFIX acl: " URI__NS_ACL \
    " SELECT ?rule WHERE {" \
    " ?rule rdf:type acl:Authorization ;" \
          " acl:%s <%s> ;" \
          " acl:mode acl:%s ;" \
          " acl:agentClass ?class ." \
    " <%s> rdf:type ?class ." \
    " }"

#define SPARQL_URI_MODE_WORLD \
    " PREFIX rdf: " URI__NS_RDF \
    " PREFIX acl: " URI__NS_ACL \
    " SELECT ?rule WHERE {" \
    " ?rule rdf:type acl:Authorization ;" \
          " acl:%s <%s> ;" \
          " acl:mode acl:%s ;" \
          " acl:agentClass " URI__FOAF_AGENT " ." \
    " }"

#define SPARQL_URI_ACL_EXISTS \
    " PREFIX rdf: " URI__NS_RDF \
    " PREFIX acl: " URI__NS_ACL \
    " SELECT ?rule WHERE {" \
    " ?rule rdf:type acl:Authorization ;" \
          " acl:%s <%s> ;" \
    " }"

typedef struct {
    int authoritative;
} authz_webid_config_rec;

static void *
create_authz_webid_dir_config(apr_pool_t *p, char *dirspec) {
    authz_webid_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->authoritative = 1;
    return conf;
}

static const command_rec
authz_webid_cmds[] = {
    AP_INIT_FLAG("AuthzWebIDAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_webid_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the WebID is not authorized by this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_webid_module;

static int
http_status_code(request_rec *r, int status_code) {
    authz_webid_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                        &authz_webid_module);
    if (status_code != OK && !conf->authoritative) {
        return DECLINED;
    } else if (status_code != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "access to %s failed, reason: WebID %s does not meet "
                      "ACL requirements to be allowed access",
                      r->uri, r->user);
    }
    return status_code;
}

void
log_stream_prefix(request_rec *r, librdf_stream *s, const char* prefix) {
    librdf_statement *st;
    while (1) {
         st = librdf_stream_get_object(s);
         ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "%s %s", prefix, librdf_statement_to_string(st));
         if (librdf_stream_next(s)) break;
    }
}

static int
query_results(request_rec *r, librdf_world *w, librdf_model *m, char *query) {
    int ret = 0;
    librdf_query *q = NULL;
    librdf_query_results *qr = NULL;

    if ((q = librdf_new_query(w, "sparql", NULL, (unsigned char *)query, NULL)) != NULL) {
        if ((qr = librdf_query_execute(q, m)) != NULL) {
            for (; !librdf_query_results_finished(qr); librdf_query_results_next(qr));
            ret = librdf_query_results_get_count(qr);
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "[ACL] [query] %d results, sparql: %s", ret, query);
            librdf_free_query_results(qr);
        } else
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_query_execute returned NULL");
        librdf_free_query(q);
    } else
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_query returned NULL");
    return ret;
}

static int
check_request_acl(request_rec *r, int req_access) {
    char *dir_path, *acl_path;
    apr_finfo_t acl_finfo;

    const char *req_uri, *dir_uri, *acl_uri, *access;
    const char *port, *par_uri, *req_file;

    librdf_world *rdf_world = NULL;
    librdf_storage *rdf_storage = NULL;
    librdf_model *rdf_model = NULL;
    librdf_parser *rdf_parser = NULL;
    librdf_uri *rdf_uri_acl = NULL,
               *rdf_uri_base = NULL;

    int ret = HTTP_FORBIDDEN;

    // dir_path: parent directory of request filename
    // acl_path: absolute path to request ACL
    dir_path = ap_make_dirstr_parent(r->pool, r->filename);
    acl_path = ap_make_full_path(r->pool, dir_path, WEBID_ACL_FNAME);

    if (apr_filepath_merge(&acl_path, NULL, acl_path, APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "Module bug?  Request filename path %s is invalid or "
                      "or not absolute for uri %s",
                      r->filename, r->uri);
        return HTTP_FORBIDDEN;
    }

    // acl_path: 403 if missing
    if ((apr_stat(&acl_finfo, acl_path, APR_FINFO_TYPE, r->pool) != APR_SUCCESS) ||
        (acl_finfo.filetype != APR_REG)) {
        return HTTP_FORBIDDEN;
    }

    // req_uri: fully qualified URI of request filename
    // dir_uri: fully qualified URI of request filename parent
    // acl_uri: fully qualified URI of request filename ACL
    // access: ACL URI of requested access
    port = ap_is_default_port(ap_get_server_port(r), r)
           ? "" : apr_psprintf(r->pool, ":%u", ap_get_server_port(r));
    req_uri = apr_psprintf(r->pool, "%s://%s%s%s%s",
                           ap_http_scheme(r), ap_get_server_name(r), port,
                           (*r->uri == '/') ? "" : "/",
                           r->uri);
    par_uri = ap_make_dirstr_parent(r->pool, r->uri);
    dir_uri = apr_psprintf(r->pool, "%s://%s%s%s%s",
                           ap_http_scheme(r), ap_get_server_name(r), port,
                           (*par_uri == '/') ? "" : "/",
                           par_uri);
    acl_uri = ap_make_full_path(r->pool, dir_uri, WEBID_ACL_FNAME);

    if (req_access == WEBID_ACCESS_READ) {
        access = "Read";
    } else if (req_access == WEBID_ACCESS_WRITE) {
        if ((req_file = strrchr(r->filename, '/')) != NULL &&
            strcmp(++req_file, WEBID_ACL_FNAME) == 0)
            access = "Control";
        else
            access = "Write";
    } else {
        access = "Control";
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "[ACL] %s (%s) %s | URI: %s | DIR: %s (%s) | ACL: %s (%s) | status: %d",
                  r->method, access, r->uri, req_uri, dir_uri, dir_path, acl_uri, acl_path, r->status);

    if ((rdf_world = librdf_new_world()) != NULL) {
        librdf_world_open(rdf_world);
        if ((rdf_storage = librdf_new_storage(rdf_world, "memory", NULL, NULL)) != NULL) {
            if ((rdf_model = librdf_new_model(rdf_world, rdf_storage, NULL)) != NULL) {
                if ((rdf_parser = librdf_new_parser(rdf_world, "turtle", NULL, NULL)) != NULL) {
                    if ((rdf_uri_base = librdf_new_uri(rdf_world, (unsigned char*)acl_uri)) != NULL) {
                        if ((rdf_uri_acl = librdf_new_uri_from_filename(rdf_world, acl_path)) != NULL) {
                            if (!librdf_parser_parse_into_model(rdf_parser, rdf_uri_acl, rdf_uri_base, rdf_model)) {
                                //log_stream_prefix(r, librdf_model_as_stream(rdf_model), "[ACL] [model]");
                                if (query_results(r, rdf_world, rdf_model,
                                    apr_psprintf(r->pool, SPARQL_URI_MODE_AGENT, "accessTo", req_uri, access, r->user)) > 0 || \
                                    query_results(r, rdf_world, rdf_model,
                                    apr_psprintf(r->pool, SPARQL_URI_MODE_AGENTCLASS, "accessTo", req_uri, access, r->user)) > 0 || \
                                    query_results(r, rdf_world, rdf_model,
                                    apr_psprintf(r->pool, SPARQL_URI_MODE_WORLD, "accessTo", req_uri, access)) > 0 || \
                                    ( ( query_results(r, rdf_world, rdf_model,
                                        apr_psprintf(r->pool, SPARQL_URI_ACL_EXISTS, "accessTo", req_uri )) == 0 ) &&
                                      ( query_results(r, rdf_world, rdf_model,
                                        apr_psprintf(r->pool, SPARQL_URI_MODE_AGENT, "defaultForNew", dir_uri, access, r->user)) > 0 || \
                                        query_results(r, rdf_world, rdf_model,
                                        apr_psprintf(r->pool, SPARQL_URI_MODE_AGENTCLASS, "defaultForNew", dir_uri, access, r->user)) > 0 || \
                                        query_results(r, rdf_world, rdf_model,
                                        apr_psprintf(r->pool, SPARQL_URI_MODE_WORLD, "defaultForNew", dir_uri, access)) > 0 ) ) ) {
                                    apr_table_set(r->headers_out, "Link", apr_psprintf(r->pool, "%s; rel=meta", acl_uri));
                                    ret = OK;
                                }
                            } else
                                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_parser_parse_into_model failed");
                            librdf_free_uri(rdf_uri_acl);
                        } else
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_uri_from_filename returned NULL");
                        librdf_free_uri(rdf_uri_base);
                    } else
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_uri returned NULL");
                    librdf_free_parser(rdf_parser);
                } else
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_parser returned NULL");
                librdf_free_model(rdf_model);
            } else
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_model returned NULL");
            librdf_free_storage(rdf_storage);
        } else
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_storage returned NULL");
        librdf_free_world(rdf_world);
    } else
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "librdf_new_world returned NULL");

    return ret;
}

static int
webid_auth_checker(request_rec *r) {
    int is_initial_req, req_access, req_method, ret;
    const char *req_dest;

    request_rec *r_dest;
    apr_uri_t apr_uri;

    if (r->filename == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "Module bug?  Request filename is missing for URI %s", r->uri);
        return http_status_code(r, OK);
    }

    if (r->user == NULL || strlen(r->user) == 0) {
        return http_status_code(r, HTTP_FORBIDDEN);
    }

    // req_access: Read, Write, or Control
    is_initial_req = ap_is_initial_req(r);
    req_access = WEBID_ACCESS_INVALID;
    req_method = (AP_METHOD_BIT << r->method_number);

    if (is_initial_req && r->method_number == M_COPY) {
        // allow COPY of a readonly source URI
        // - target URI check happens by subrequest
        req_access = WEBID_ACCESS_READ;

    } else if (req_method == (req_method & WEBID_M_READ)) {
        // check the acl:Read method bitmask
        req_access = WEBID_ACCESS_READ;

    } else if (req_method == (req_method & WEBID_M_WRITE)) {
        // check the acl:Write method bitmask
        // - writes to ACL URIs are acl:Control (handled internally)
        req_access = WEBID_ACCESS_WRITE;

    } else {
        // unhandled methods require acl:Control
        req_access = WEBID_ACCESS_CONTROL;
    }

    ret = HTTP_FORBIDDEN;

    if (is_initial_req && (r->method_number == M_COPY || r->method_number == M_MOVE)) {
        req_dest = apr_table_get(r->headers_in, "Destination");
        if (req_dest == NULL) {
            const char *nscp_host = apr_table_get(r->headers_in, "Host");
            const char *nscp_path = apr_table_get(r->headers_in, "New-uri");
            if (nscp_host != NULL && nscp_path != NULL)
                req_dest = apr_psprintf(r->pool, "http://%s%s", nscp_host, nscp_path);
        }
        if (req_dest != NULL) {
            if ((apr_uri_parse(r->pool, req_dest, &apr_uri) == APR_SUCCESS) &&
                (apr_uri.scheme != NULL && strcmp(apr_uri.scheme, ap_http_scheme(r)) == 0) &&
                (apr_uri.hostname != NULL && strcmp(apr_uri.hostname, ap_get_server_name(r)) == 0)) {
                req_dest = apr_uri_unparse(r->pool, &apr_uri, APR_URI_UNP_OMITSITEPART);
                r_dest = ap_sub_req_method_uri(r->method, req_dest, r, NULL);
                if ((ret = check_request_acl(r, req_access)) == OK)
                    ret = check_request_acl(r_dest, WEBID_ACCESS_WRITE);
            } else {
                ret = HTTP_BAD_GATEWAY;
            }
        }
    } else {
        ret = check_request_acl(r, req_access);
    }

    return http_status_code(r, ret);
}

static int
webid_log_transaction(request_rec *r) {
    if (ap_is_HTTP_SUCCESS(r->status)) {
        if (r->method_number == M_PUT) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s %s | status: %d", r->method, r->uri, r->status);
        } else if (r->method_number == M_DELETE) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s %s | status: %d", r->method, r->uri, r->status);
        } else if (r->method_number == M_MKCOL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s %s | status: %d", r->method, r->uri, r->status);
        } else if (r->method_number == M_COPY) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s %s | status: %d", r->method, r->uri, r->status);
        } else if (r->method_number == M_MOVE) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s %s | status: %d", r->method, r->uri, r->status);
        }
    }
    return DECLINED;
}

static void
register_hooks(apr_pool_t *p) {
    static const char * const aszPost[]={ "mod_authz_user.c", NULL };

    ap_hook_auth_checker(webid_auth_checker, NULL, aszPost, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(webid_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA
authz_webid_module = {
    STANDARD20_MODULE_STUFF,
    create_authz_webid_dir_config, /* dir config creater */
    NULL,                          /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    authz_webid_cmds,              /* command apr_table_t */
    register_hooks                 /* register hooks */
};
