#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/runtime_config.h"
#include "../../include/common.h"

// Handler: GET /api/v1/system/health
enum MHD_Result api_system_health(struct MHD_Connection *connection, 
                                  struct api_context *ctx) {
    const char *json = "{\"status\":\"healthy\",\"version\":\"2.0.0\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), (void*)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

// Handler: GET /api/v1/system/settings
enum MHD_Result api_system_get_settings(struct MHD_Connection *connection, 
                                        struct api_context *ctx) {
    json_object *j_settings = json_object_new_object();
    
    if (ctx->config) {
        json_object_object_add(j_settings, "interface", json_object_new_string(ctx->config->interface));
        json_object_object_add(j_settings, "log_level", json_object_new_int(ctx->config->log_level));
        json_object_object_add(j_settings, "geoip_enabled", json_object_new_boolean(ctx->config->geoip_db_path != NULL));
        
        // Thresholds
        json_object_object_add(j_settings, "syn_flood_rate", json_object_new_int(ctx->config->syn_flood_rate));
        json_object_object_add(j_settings, "udp_flood_rate", json_object_new_int(ctx->config->udp_flood_rate));
        json_object_object_add(j_settings, "icmp_flood_rate", json_object_new_int(ctx->config->icmp_flood_rate));
        json_object_object_add(j_settings, "dns_amp_rate", json_object_new_int(ctx->config->dns_amp_rate));
        json_object_object_add(j_settings, "max_frags", json_object_new_int(ctx->config->max_frags));
    }
    
    const char *json_str = json_object_to_json_string(j_settings);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(j_settings);
    return ret;
}

// Handler: POST /api/v1/system/settings
enum MHD_Result api_system_update_settings(struct MHD_Connection *connection, 
                                           struct api_context *ctx,
                                           const char *upload_data, size_t size) {
    
    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        const char *err = "{\"error\":\"Invalid JSON\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        return MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
    }

    struct json_object *j_syn, *j_udp, *j_icmp, *j_dns, *j_frags;
    
    if (json_object_object_get_ex(root, "syn_flood_rate", &j_syn)) 
        ctx->config->syn_flood_rate = json_object_get_int(j_syn);
    
    if (json_object_object_get_ex(root, "udp_flood_rate", &j_udp)) 
        ctx->config->udp_flood_rate = json_object_get_int(j_udp);
        
    if (json_object_object_get_ex(root, "icmp_flood_rate", &j_icmp)) 
        ctx->config->icmp_flood_rate = json_object_get_int(j_icmp);
        
    if (json_object_object_get_ex(root, "dns_amp_rate", &j_dns)) 
        ctx->config->dns_amp_rate = json_object_get_int(j_dns);
        
    if (json_object_object_get_ex(root, "max_frags", &j_frags)) 
        ctx->config->max_frags = json_object_get_int(j_frags);

    // Update BPF Map if FD is available
    if (ctx->fds && ctx->fds->config_map_fd > 0) {
        struct attacks_config_t cfg = {
            .syn_flood_rate = ctx->config->syn_flood_rate,
            .udp_flood_rate = ctx->config->udp_flood_rate,
            .icmp_flood_rate = ctx->config->icmp_flood_rate,
            .dns_amp_rate = ctx->config->dns_amp_rate,
            .max_frags = ctx->config->max_frags
        };
        uint32_t key = 0;
        bpf_map_update_elem(ctx->fds->config_map_fd, &key, &cfg, BPF_ANY);
        printf("DEBUG: Updated BPF config map. SYN=%u UDP=%u\n", cfg.syn_flood_rate, cfg.udp_flood_rate);
    }

    json_object_put(root); // Free JSON object
    
    const char *json = "{\"status\":\"settings updated\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), (void*)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}
