#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/database.h"

// Helper to get FDs from user_data
// struct map_fds is defined in api_handlers.h

// Handler: GET /api/v1/attacks
enum MHD_Result api_attacks_list(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *year, const char *month) {
    struct map_fds *fds = ctx->fds;
    
    json_object *json_attacks = json_object_new_array();
    
    struct attack_info *attacks = NULL;
    int attack_count = get_attack_info(&attacks, fds->attack_info_array_fd, fds->attack_count_fd);
    
    // Calculate boot time for correct timestamp conversion
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t boot_time = time(NULL) - ts.tv_sec;

    if (attacks) {
        for (int i = 0; i < attack_count; i++) {
            json_object *json_attack = json_object_new_object();
            
            char time_str[30];
            time_t timestamp = boot_time + (time_t)(attacks[i].timestamp / 1000000000); 
            struct tm *tm_info = localtime(&timestamp);
            if (tm_info) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                snprintf(time_str, sizeof(time_str), "Invalid timestamp");
            }
            
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(attacks[i].src_ip), ip_str, sizeof(ip_str));
            
            json_object_object_add(json_attack, "id", json_object_new_int(i)); // Use index as ID for now
            json_object_object_add(json_attack, "timestamp", json_object_new_string(time_str));
            json_object_object_add(json_attack, "src_ip", json_object_new_string(ip_str));
            json_object_object_add(json_attack, "protocol", json_object_new_string(get_proto_name(attacks[i].protocol)));
            json_object_object_add(json_attack, "packets", json_object_new_int(attacks[i].packets));
            json_object_object_add(json_attack, "bytes", json_object_new_int64(attacks[i].bytes));
            
            // Add status
            json_object_object_add(json_attack, "status", json_object_new_string("active"));
            
            json_object_array_add(json_attacks, json_attack);
        }
        free(attacks);
    }
    
    // Fetch historical attacks from DB
    struct attack_record *history = NULL;
    int history_count = 0;
    // Use the global database handle 'g_db' declared in main.c
    extern struct database *g_db; 
    
    if (g_db && g_db->is_open) {
        // Fetch up to 50 historical attacks
        database_get_attacks_history(g_db, &history, &history_count, 50);
    }
    
    if (history) {
        for (int i = 0; i < history_count; i++) {
             // Create JSON for historical attack
            json_object *json_attack = json_object_new_object();
            
            char time_str[30];
            time_t timestamp = (time_t)(history[i].timestamp);
            struct tm *tm_info = localtime(&timestamp);
            if (tm_info) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                snprintf(time_str, sizeof(time_str), "Invalid timestamp");
            }
            
            json_object_object_add(json_attack, "id", json_object_new_int64(history[i].id));
            json_object_object_add(json_attack, "timestamp", json_object_new_string(time_str));
            json_object_object_add(json_attack, "src_ip", json_object_new_string(history[i].src_ip));
            json_object_object_add(json_attack, "protocol", json_object_new_string(history[i].attack_type)); // Using type as protocol for now
            json_object_object_add(json_attack, "packets", json_object_new_int(history[i].packets));
            json_object_object_add(json_attack, "bytes", json_object_new_int64(history[i].bytes));
            json_object_object_add(json_attack, "status", json_object_new_string(history[i].status));
            
            json_object_array_add(json_attacks, json_attack);
        }
        free(history);
    }
    
    const char *json_str = json_object_to_json_string_ext(json_attacks, JSON_C_TO_STRING_PRETTY);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(json_attacks);
    return ret;
}

// Handler: GET /api/v1/attacks/:id
enum MHD_Result api_attacks_get(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                int id) {
    // Stub implementation
    json_object *json_attack = json_object_new_object();
    json_object_object_add(json_attack, "id", json_object_new_int(id));
    json_object_object_add(json_attack, "status", json_object_new_string("resolved"));
    
    const char *json_str = json_object_to_json_string(json_attack);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(json_attack);
    return ret;
}
