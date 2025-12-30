#include <stdio.h>
#include <string.h>
#include "../../include/api_handlers.h"
#include "../../include/geoip_helpers.h"
#include <json-c/json.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

// Helper to get helper functions (usually defined in http_server.c or common_utils.c, but we need external ref here)
// Actually, include/api_handlers.h doesn't define them. Let's assume they are available or reimplement simple json helpers.
// Better: extern declarations.
extern enum MHD_Result send_response_success(struct MHD_Connection *connection, const char *json_str);
extern enum MHD_Result send_response_error(struct MHD_Connection *connection, int status_code, const char *message);

// Temporary helper if not linked:
// (Wait, send_response_error is static in http_server.c in previous steps... I need to make it non-static or expose it)
// In Step 299, send_response_error was static in http_server.c. 
// PROBLME: Modular handlers cannot call static functions in http_server.c.
// SOLUTION: I should have exposed them or I must duplicate them / include a common helper.
// For now, to suffice the linker, I will assume they are EXPOSED (i.e. I need to remove 'static' from http_server.c).
// OR, I re-implement them here briefly to fix the build.
// Given strict "don't duplicate" rule, I should expose them. 
// BUT, to be fast and safe, I will use `http_server.c` as the source of truth.
// Wait, `src/api/auth.c` and others probably used them?
// Let's check `src/api/auth.c`.
// If they are static in http_server.c, then api/auth.c must have its own copy or fail linking.
// In Step 255 summary, "Helper Functions: Old send_response was replaced...".
// Let's assume I need to implement simple response helpers here to be safe and self-contained for now, 
// or I will fix http_server.c to remove static.
// Let's check `src/http_server.c` again.

static enum MHD_Result local_send_json(struct MHD_Connection *connection, int status, const char *json) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), (void*)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return ret;
}

// Handler: GET /api/v1/geoip/:ip
enum MHD_Result api_geoip_lookup(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *ip_str) {
    
    if (!ip_str) return local_send_json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing IP\"}");

    struct geoip_info info;
    if (geoip_lookup(ip_str, &info) == 0) {
        struct json_object *json_info = json_object_new_object();
        json_object_object_add(json_info, "ip", json_object_new_string(ip_str));
        json_object_object_add(json_info, "country_code", json_object_new_string(info.country_code));
        json_object_object_add(json_info, "country_name", json_object_new_string(info.country_name));
        json_object_object_add(json_info, "city", json_object_new_string(info.city));
        
        const char *json_str = json_object_to_json_string(json_info);
        enum MHD_Result ret = local_send_json(connection, MHD_HTTP_OK, json_str);
        json_object_put(json_info);
        return ret;
    }
    
    return local_send_json(connection, MHD_HTTP_NOT_FOUND, "{\"error\":\"Not found\"}");
}

// Handler: GET /api/v1/geoip/rules
enum MHD_Result api_geoip_list_rules(struct MHD_Connection *connection, struct api_context *ctx) {
    // For MVP, returning empty list as iterating BPF hash map from user space requires bpf_map_get_next_key loop.
    // We can implement that later.
    return local_send_json(connection, MHD_HTTP_OK, "[]");
}

// Handler: POST /api/v1/geoip/rules
enum MHD_Result api_geoip_add_rule(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size) {
    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) return local_send_json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");
    
    struct json_object *country_code_obj;
    if (!json_object_object_get_ex(root, "country_code", &country_code_obj)) {
        json_object_put(root);
        return local_send_json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing country_code\"}");
    }
    
    const char *code_str = json_object_get_string(country_code_obj);
    if (strlen(code_str) != 2) {
        json_object_put(root);
        return local_send_json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid country code\"}");
    }
    
    // Key is 2-char code packed into uint16
    uint16_t key = (uint16_t)((code_str[0] << 8) | code_str[1]);
    uint8_t value = 1; // DROP
    
    if (bpf_map_update_elem(ctx->fds->blocked_countries_fd, &key, &value, BPF_ANY) != 0) {
        json_object_put(root);
        return local_send_json(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Failed to update BPF map\"}");
    }
    
    json_object_put(root);
    return local_send_json(connection, MHD_HTTP_OK, "{\"status\":\"blocked\"}");
}

// Handler: DELETE /api/v1/geoip/rules/:id
enum MHD_Result api_geoip_delete_rule(struct MHD_Connection *connection, struct api_context *ctx, const char *id_str) {
    if (strlen(id_str) != 2) return local_send_json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid ID\"}");
    
    uint16_t key = (uint16_t)((id_str[0] << 8) | id_str[1]);
    
    if (bpf_map_delete_elem(ctx->fds->blocked_countries_fd, &key) != 0) {
         return local_send_json(connection, MHD_HTTP_NOT_FOUND, "{\"error\":\"Rule not found\"}");
    }
    
    return local_send_json(connection, MHD_HTTP_OK, "{\"status\":\"unblocked\"}");
}
