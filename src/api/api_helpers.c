// Helper functions for security API
#include <microhttpd.h>
#include <string.h>

struct MHD_Response *create_response(int status_code, const char *content, const char *content_type) {
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(content), (void*)content, MHD_RESPMEM_MUST_COPY
    );
    MHD_add_response_header(response, "Content-Type", content_type);
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    return response;
}

struct MHD_Response *create_json_response(int status_code, const char *json) {
    return create_response(status_code, json, "application/json");
}
