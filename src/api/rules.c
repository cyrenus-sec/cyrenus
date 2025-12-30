#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/common.h"



static const char* get_proto_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "UNKNOWN";
    }
}

// Handler: GET /api/v1/rules
enum MHD_Result api_rules_list(struct MHD_Connection *connection, 
                               struct api_context *ctx) {
    struct map_fds *fds = ctx->fds;
    
    json_object *json_rules = json_object_new_array();
    
    struct rule_key_t key = {0}, next_key = {0};
    struct rule_t rule;
    
    if (fds->rules_fd >= 0) {
        while (bpf_map_get_next_key(fds->rules_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(fds->rules_fd, &next_key, &rule) == 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key.ip, ip_str, sizeof(ip_str));

                json_object *json_rule = json_object_new_object();
                json_object_object_add(json_rule, "ip", json_object_new_string(ip_str));
                json_object_object_add(json_rule, "port", json_object_new_int(ntohs(next_key.port)));
                json_object_object_add(json_rule, "proto", json_object_new_string(get_proto_name(next_key.proto)));
                json_object_object_add(json_rule, "port_start", json_object_new_int(ntohs(rule.port_start)));
                json_object_object_add(json_rule, "port_end", json_object_new_int(ntohs(rule.port_end)));
                json_object_object_add(json_rule, "action", json_object_new_int(rule.action));
                json_object_array_add(json_rules, json_rule);
            }
            key = next_key;
        }
    }

    const char *json_str = json_object_to_json_string(json_rules);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(json_rules);
    return ret;
}

// Handler: POST /api/v1/rules
enum MHD_Result api_rules_create(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *upload_data, size_t size) {
    struct map_fds *fds = ctx->fds;
    struct MHD_Response *response;
    
    json_object *json_rule = json_tokener_parse(upload_data);
    if (!json_rule) {
        const char *err = "{\"error\":\"Invalid JSON\"}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return MHD_YES;
    }
    
    struct rule_t rule = {0};
    struct rule_key_t key = {0};
    
    // Parse fields
    json_object *j_ip, *j_port, *j_proto, *j_action;
    
    // IP
    if (json_object_object_get_ex(json_rule, "ip", &j_ip)) {
        if (inet_pton(AF_INET, json_object_get_string(j_ip), &key.ip) != 1) {
             // Handle error
        }
    }
    
    // Port
    if (json_object_object_get_ex(json_rule, "port", &j_port)) {
        int port = json_object_get_int(j_port);
        key.port = htons(port);
        rule.port_start = htons(port);
        rule.port_end = htons(port);
    }
    
    // Proto
    if (json_object_object_get_ex(json_rule, "proto", &j_proto)) {
        const char *proto = json_object_get_string(j_proto);
        if (strcasecmp(proto, "tcp") == 0) key.proto = IPPROTO_TCP;
        else if (strcasecmp(proto, "udp") == 0) key.proto = IPPROTO_UDP;
        else if (strcasecmp(proto, "icmp") == 0) key.proto = IPPROTO_ICMP;
    }
    rule.proto = key.proto;
    
    // Action
    rule.action = 1; // Default drop
    if (json_object_object_get_ex(json_rule, "action", &j_action)) {
        const char *action = json_object_get_string(j_action);
        if (strcasecmp(action, "pass") == 0) rule.action = 2;
    }

    if (bpf_map_update_elem(fds->rules_fd, &key, &rule, BPF_ANY) != 0) {
        const char *err = "{\"error\":\"Failed to update BPF map\"}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
    } else {
        const char *succ = "{\"status\":\"Rule added\"}";
        response = MHD_create_response_from_buffer(strlen(succ), (void*)succ, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
    }
    
    json_object_put(json_rule);
    return MHD_YES;
}

// Handler: DELETE /api/v1/rules/:id
enum MHD_Result api_rules_delete(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *id_str) {
    // id_str expected format: IP_PORT_PROTO e.g. "192.168.1.1_80_6"
    struct map_fds *fds = ctx->fds;
    
    char ip_str[INET_ADDRSTRLEN];
    int port, proto;
    
    if (sscanf(id_str, "%15[^_]_%d_%d", ip_str, &port, &proto) != 3) {
         // Error
    }
    
    struct rule_key_t key = {0};
    inet_pton(AF_INET, ip_str, &key.ip);
    key.port = htons(port);
    key.proto = proto;
    
    if (bpf_map_delete_elem(fds->rules_fd, &key) != 0) {
        // Error
    }
    
    const char *succ = "{\"status\":\"Rule deleted\"}";
    struct MHD_Response *rs = MHD_create_response_from_buffer(strlen(succ), (void*)succ, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(rs, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, rs);
    MHD_destroy_response(rs);
    return ret;
}
