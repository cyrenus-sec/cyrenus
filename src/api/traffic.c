#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/common.h"



// Handler: GET /api/v1/traffic/stats
enum MHD_Result api_traffic_stats(struct MHD_Connection *connection, 
                                  struct api_context *ctx) {
    struct map_fds *fds = ctx->fds;
    
    json_object *json_traffic = json_object_new_array();
    
    struct traffic_info_t info;
    struct flow_key_t key = {0}, next_key = {0};
    int count = 0;
    
    // Iterate through traffic map
    if (fds->traffic_fd >= 0) {
        // Start iteration by using an all-zero key if needed, or better, NULL
        // For bpf_map_get_next_key, starting with a zero key is common but NULL is standard for 'first'
        // Actually, some libbpf wrappers use key = 0.
        while (bpf_map_get_next_key(fds->traffic_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(fds->traffic_fd, &next_key, &info) == 0) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &info.src_ip, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &info.dst_ip, dst_ip, sizeof(dst_ip));

                json_object *json_info = json_object_new_object();
                json_object_object_add(json_info, "src_ip", json_object_new_string(src_ip));
                json_object_object_add(json_info, "dst_ip", json_object_new_string(dst_ip));
                json_object_object_add(json_info, "src_port", json_object_new_int(info.src_port));
                json_object_object_add(json_info, "dst_port", json_object_new_int(info.dst_port));
                json_object_object_add(json_info, "proto", json_object_new_int(info.proto));
                json_object_object_add(json_info, "bytes", json_object_new_int64(info.bytes));
                json_object_object_add(json_info, "packets", json_object_new_int(info.packets));
                
                json_object_array_add(json_traffic, json_info);
                
                if (++count >= 100) break; // Limit to 100 entries for UI performance
            }
            key = next_key;
        }
    }

    const char *json_str = json_object_to_json_string(json_traffic);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(json_traffic);
    return ret;
}
