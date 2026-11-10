#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../include/api_handlers.h"
#include "../../include/database.h"

// Handler: GET /api/v1/iplists/:type
enum MHD_Result api_iplists_get(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *list_type) {
    
    // In real implementation, query DB for lists where list_type matches
    // struct ip_list_record *records;
    // int count = database_get_ip_lists(ctx->db, list_type, &records);
    
    // Stub response
    json_object *json_lists = json_object_new_array();
    
    // Mock data
    if (strcmp(list_type, "blacklist") == 0) {
        json_object *item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_int(1));
        json_object_object_add(item, "ip_address", json_object_new_string("10.0.0.50"));
        json_object_object_add(item, "reason", json_object_new_string("Manual block"));
        json_object_array_add(json_lists, item);
    }
    
    const char *json_str = json_object_to_json_string(json_lists);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(json_lists);
    return ret;
}

// Handler: POST /api/v1/iplists
enum MHD_Result api_iplists_add(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *upload_data, size_t size) {
    if (!upload_data || size == 0) {
        const char *err = "{\"error\":\"Missing request body\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        const char *err = "{\"error\":\"Invalid JSON\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
    }
    
    // Parse IP, list_type, etc. and insert into DB
    // database_insert_ip_list(ctx->db, ...);
    
    const char *resp = "{\"status\":\"IP added to list\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(resp), (void*)resp, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    
    MHD_destroy_response(response);
    json_object_put(root);
    return ret;
}

// Handler: DELETE /api/v1/iplists/:id
enum MHD_Result api_iplists_delete(struct MHD_Connection *connection, 
                                   struct api_context *ctx,
                                   int id) {
    // database_delete_ip_list(ctx->db, id);
    
    const char *resp = "{\"status\":\"IP removed from list\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(resp), (void*)resp, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    
    MHD_destroy_response(response);
    return ret;
}
