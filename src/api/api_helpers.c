// Shared HTTP JSON, CORS, and security response helpers
#include <microhttpd.h>
#include <json-c/json.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>
#include "../../include/api_handlers.h"
#include "../../include/runtime_config.h"

#ifndef MHD_HTTP_TOO_MANY_REQUESTS
#define MHD_HTTP_TOO_MANY_REQUESTS 429
#endif

static _Thread_local int tls_last_status = MHD_HTTP_OK;
static const struct runtime_config *g_http_cfg = NULL;

void api_helpers_set_config(const struct runtime_config *cfg) {
    g_http_cfg = cfg;
}

static int origin_is_allowed(const char *configured, const char *req_origin) {
    if (!configured || configured[0] == '\0' || !req_origin || req_origin[0] == '\0') {
        return 0;
    }
    if (strcmp(configured, "*") == 0) {
        return 1;
    }

    size_t req_len = strlen(req_origin);
    const char *p = configured;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == '\0') break;
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t') p++;
        size_t tok_len = (size_t)(p - start);
        if (tok_len == req_len && strncasecmp(start, req_origin, tok_len) == 0) {
            return 1;
        }
    }
    return 0;
}

void api_apply_response_headers(struct MHD_Connection *connection, struct MHD_Response *response) {
    if (!response) return;

    // Hardened security headers
    MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
    MHD_add_response_header(response, "X-Frame-Options", "DENY");
    MHD_add_response_header(response, "Referrer-Policy", "no-referrer");
    MHD_add_response_header(response, "Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    MHD_add_response_header(
        response,
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self' ws: wss:; frame-ancestors 'none'"
    );

    // Explicit same-origin default CORS policy; emit ACAO only when configured and matched
    const char *cfg_origin = (g_http_cfg && g_http_cfg->cors_origin[0]) ? g_http_cfg->cors_origin : NULL;
    const char *req_origin = connection
        ? MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Origin")
        : NULL;

    MHD_add_response_header(response, "Vary", "Origin");

    if (cfg_origin) {
        if (strcmp(cfg_origin, "*") == 0) {
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
            MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With");
        } else if (req_origin && origin_is_allowed(cfg_origin, req_origin)) {
            MHD_add_response_header(response, "Access-Control-Allow-Origin", req_origin);
            MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With");
        }
    }
}

enum MHD_Result api_send_json(struct MHD_Connection *connection, int status_code, const char *json_str) {
    const char *body = json_str ? json_str : "{}";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY
    );
    if (!response) return MHD_NO;

    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Cache-Control", "no-store");
    api_apply_response_headers(connection, response);

    enum MHD_Result ret = MHD_queue_response(connection, (unsigned int)status_code, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result api_send_error(struct MHD_Connection *connection, int status_code, const char *message) {
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "error", json_object_new_string(message ? message : "Error"));
    const char *json_str = json_object_to_json_string(obj);
    enum MHD_Result ret = api_send_json(connection, status_code, json_str);
    json_object_put(obj);
    return ret;
}

enum MHD_Result api_send_rate_limited(struct MHD_Connection *connection, int retry_after_sec, const char *message) {
    int retry = retry_after_sec > 0 ? retry_after_sec : 60;
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "error", json_object_new_string(message ? message : "Too many requests"));
    json_object_object_add(obj, "retry_after", json_object_new_int(retry));
    const char *body = json_object_to_json_string(obj);

    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY
    );
    json_object_put(obj);
    if (!response) return MHD_NO;

    char retry_buf[32];
    snprintf(retry_buf, sizeof(retry_buf), "%d", retry);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Cache-Control", "no-store");
    MHD_add_response_header(response, "Retry-After", retry_buf);
    api_apply_response_headers(connection, response);

    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_TOO_MANY_REQUESTS, response);
    MHD_destroy_response(response);
    return ret;
}

struct MHD_Response *create_response(int status_code, const char *content, const char *content_type) {
    tls_last_status = status_code;
    const char *body = content ? content : "";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY
    );
    if (!response) return NULL;
    MHD_add_response_header(response, "Content-Type", content_type ? content_type : "text/plain");
    MHD_add_response_header(response, "Cache-Control", "no-store");
    return response;
}

struct MHD_Response *create_json_response(int status_code, const char *json) {
    return create_response(status_code, json, "application/json");
}

int api_security_last_status(void) {
    int s = tls_last_status;
    tls_last_status = MHD_HTTP_OK;
    return s;
}
