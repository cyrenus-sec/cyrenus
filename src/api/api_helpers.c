// Shared HTTP JSON and CORS response helpers
#include <microhttpd.h>
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>
#include "../../include/api_handlers.h"

static _Thread_local int tls_last_status = MHD_HTTP_OK;

static void add_cors_headers(struct MHD_Response *response) {
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With");
    MHD_add_response_header(response, "Cache-Control", "no-store");
}

enum MHD_Result api_send_json(struct MHD_Connection *connection, int status_code, const char *json_str) {
    const char *body = json_str ? json_str : "{}";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY
    );
    if (!response) return MHD_NO;

    MHD_add_response_header(response, "Content-Type", "application/json");
    add_cors_headers(response);

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

struct MHD_Response *create_response(int status_code, const char *content, const char *content_type) {
    tls_last_status = status_code;
    const char *body = content ? content : "";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY
    );
    if (!response) return NULL;
    MHD_add_response_header(response, "Content-Type", content_type ? content_type : "text/plain");
    add_cors_headers(response);
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
