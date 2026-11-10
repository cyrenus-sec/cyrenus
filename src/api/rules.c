#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/database.h"
#include "../../include/common.h"

static int parse_proto_str(const char *proto, uint8_t *out) {
    if (!proto || proto[0] == '\0') {
        *out = IPPROTO_TCP;
        return 0;
    }
    if (strcasecmp(proto, "all") == 0 || strcasecmp(proto, "any") == 0 || strcmp(proto, "0") == 0) {
        *out = 0;
        return 0;
    }
    if (strcasecmp(proto, "tcp") == 0 || strcmp(proto, "6") == 0) {
        *out = IPPROTO_TCP;
        return 0;
    }
    if (strcasecmp(proto, "udp") == 0 || strcmp(proto, "17") == 0) {
        *out = IPPROTO_UDP;
        return 0;
    }
    if (strcasecmp(proto, "icmp") == 0 || strcmp(proto, "1") == 0) {
        *out = IPPROTO_ICMP;
        return 0;
    }
    return -1;
}

// Handler: GET /api/v1/rules
enum MHD_Result api_rules_list(struct MHD_Connection *connection,
                               struct api_context *ctx) {
    struct map_fds *fds = ctx ? ctx->fds : NULL;
    json_object *json_rules = json_object_new_array();

    // Load DB rules first (works in both dry-run and live mode)
    struct rule_record *db_rules = NULL;
    int db_count = 0;
    if (ctx && ctx->db && ctx->db->is_open) {
        database_list_rules(ctx->db, &db_rules, &db_count);
    }

    for (int i = 0; i < db_count; i++) {
        char rule_key[64];
        snprintf(rule_key, sizeof(rule_key), "%s_%u_%u",
                 db_rules[i].ip_address, db_rules[i].port_start, db_rules[i].protocol);

        json_object *j_rule = json_object_new_object();
        json_object_object_add(j_rule, "id", json_object_new_int(db_rules[i].id));
        json_object_object_add(j_rule, "rule_key", json_object_new_string(rule_key));
        json_object_object_add(j_rule, "ip", json_object_new_string(db_rules[i].ip_address));
        json_object_object_add(j_rule, "port", json_object_new_int(db_rules[i].port_start));
        json_object_object_add(j_rule, "proto", json_object_new_string(get_proto_name(db_rules[i].protocol)));
        json_object_object_add(j_rule, "proto_num", json_object_new_int(db_rules[i].protocol));
        json_object_object_add(j_rule, "port_start", json_object_new_int(db_rules[i].port_start));
        json_object_object_add(j_rule, "port_end", json_object_new_int(db_rules[i].port_end));
        json_object_object_add(j_rule, "action", json_object_new_int(db_rules[i].action));
        json_object_object_add(j_rule, "description", json_object_new_string(db_rules[i].description));
        json_object_object_add(j_rule, "enabled", json_object_new_boolean(db_rules[i].enabled));
        json_object_array_add(json_rules, j_rule);
    }

    // Merge any rules directly in BPF map that weren't loaded from DB
    if (fds && fds->rules_fd >= 0) {
        struct rule_key_t key = {0}, next_key = {0};
        struct rule_t rule;
        void *cur_key = NULL;

        while (bpf_map_get_next_key(fds->rules_fd, cur_key, &next_key) == 0) {
            if (bpf_map_lookup_elem(fds->rules_fd, &next_key, &rule) == 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key.ip, ip_str, sizeof(ip_str));
                uint16_t port_host = ntohs(next_key.port);

                int exists_in_db = 0;
                for (int i = 0; i < db_count; i++) {
                    if (strcmp(db_rules[i].ip_address, ip_str) == 0 &&
                        db_rules[i].port_start == port_host &&
                        db_rules[i].protocol == next_key.proto) {
                        exists_in_db = 1;
                        break;
                    }
                }

                if (!exists_in_db) {
                    char rule_key[64];
                    snprintf(rule_key, sizeof(rule_key), "%s_%u_%u", ip_str, port_host, next_key.proto);

                    json_object *j_rule = json_object_new_object();
                    json_object_object_add(j_rule, "rule_key", json_object_new_string(rule_key));
                    json_object_object_add(j_rule, "ip", json_object_new_string(ip_str));
                    json_object_object_add(j_rule, "port", json_object_new_int(port_host));
                    json_object_object_add(j_rule, "proto", json_object_new_string(get_proto_name(next_key.proto)));
                    json_object_object_add(j_rule, "proto_num", json_object_new_int(next_key.proto));
                    json_object_object_add(j_rule, "port_start", json_object_new_int(ntohs(rule.port_start)));
                    json_object_object_add(j_rule, "port_end", json_object_new_int(ntohs(rule.port_end)));
                    json_object_object_add(j_rule, "action", json_object_new_int(rule.action));
                    json_object_object_add(j_rule, "enabled", json_object_new_boolean(true));
                    json_object_array_add(json_rules, j_rule);
                }
            }
            key = next_key;
            cur_key = &key;
        }
    }

    if (db_rules) {
        database_free_rule_list(db_rules, db_count);
    }

    const char *json_str = json_object_to_json_string(json_rules);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(json_rules);
    return ret;
}

// Handler: POST /api/v1/rules
enum MHD_Result api_rules_create(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *upload_data, size_t size) {
    struct map_fds *fds = ctx ? ctx->fds : NULL;

    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    json_object *json_rule = json_tokener_parse(upload_data);
    if (!json_rule) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    struct rule_t rule = {0};
    struct rule_key_t key = {0};

    json_object *j_ip = NULL, *j_port = NULL, *j_proto = NULL, *j_action = NULL, *j_desc = NULL;
    const char *ip_str = NULL;
    if (json_object_object_get_ex(json_rule, "ip", &j_ip)) {
        ip_str = json_object_get_string(j_ip);
    }
    if (!ip_str || inet_pton(AF_INET, ip_str, &key.ip) != 1) {
        json_object_put(json_rule);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid or missing IPv4 address");
    }

    int port = 0;
    if (json_object_object_get_ex(json_rule, "port", &j_port)) {
        port = json_object_get_int(j_port);
        if (port < 0 || port > 65535) {
            json_object_put(json_rule);
            return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Port must be between 0 and 65535");
        }
    }
    key.port = htons((uint16_t)port);
    rule.port_start = htons((uint16_t)port);
    rule.port_end = htons((uint16_t)port);

    uint8_t proto_val = IPPROTO_TCP;
    if (json_object_object_get_ex(json_rule, "proto", &j_proto)) {
        const char *proto_s = json_object_get_string(j_proto);
        if (parse_proto_str(proto_s, &proto_val) != 0) {
            json_object_put(json_rule);
            return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid protocol (use tcp, udp, icmp, or all)");
        }
    }
    key.proto = proto_val;
    rule.proto = proto_val;

    rule.action = ACTION_DROP;
    if (json_object_object_get_ex(json_rule, "action", &j_action)) {
        const char *action = json_object_get_string(j_action);
        if (action) {
            if (strcasecmp(action, "pass") == 0 || strcmp(action, "2") == 0) {
                rule.action = ACTION_PASS;
            } else if (strcasecmp(action, "drop") == 0 || strcmp(action, "1") == 0) {
                rule.action = ACTION_DROP;
            } else {
                json_object_put(json_rule);
                return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid action (use drop or pass)");
            }
        }
    }

    const char *desc = "";
    if (json_object_object_get_ex(json_rule, "description", &j_desc)) {
        const char *s = json_object_get_string(j_desc);
        if (s) desc = s;
    }

    if (fds && fds->rules_fd >= 0) {
        if (bpf_map_update_elem(fds->rules_fd, &key, &rule, BPF_ANY) != 0) {
            json_object_put(json_rule);
            return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to update BPF rules map");
        }
        // If allowing all traffic for this IP, lift any active auto-block immediately
        if (rule.action == ACTION_PASS && fds->auto_block_fd >= 0) {
            bpf_map_delete_elem(fds->auto_block_fd, &key.ip);
        }
    }

    if (ctx && ctx->db && ctx->db->is_open) {
        struct rule_record rec = {0};
        snprintf(rec.ip_address, sizeof(rec.ip_address), "%s", ip_str);
        rec.port_start = (uint16_t)port;
        rec.port_end = (uint16_t)port;
        rec.protocol = proto_val;
        rec.action = rule.action;
        snprintf(rec.description, sizeof(rec.description), "%s", desc);
        rec.enabled = true;
        database_insert_rule(ctx->db, &rec);
    }

    json_object_put(json_rule);
    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"Rule added\"}");
}

// Handler: DELETE /api/v1/rules/:id
enum MHD_Result api_rules_delete(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *id_str) {
    struct map_fds *fds = ctx ? ctx->fds : NULL;
    char ip_str[INET_ADDRSTRLEN] = {0};
    int port = 0, proto = 0;

    if (!id_str || id_str[0] == '\0') {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid rule ID");
    }

    // Support both IP_PORT_PROTO tuple ("1.2.3.4_80_6") and numeric DB ID
    if (sscanf(id_str, "%15[^_]_%d_%d", ip_str, &port, &proto) == 3) {
        if (port < 0 || port > 65535 || proto < 0 || proto > 255) {
            return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid rule tuple values");
        }

        struct rule_key_t key = {0};
        if (inet_pton(AF_INET, ip_str, &key.ip) != 1) {
            return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid IP address in rule ID");
        }
        key.port = htons((uint16_t)port);
        key.proto = (uint8_t)proto;

        int deleted = 0;
        if (fds && fds->rules_fd >= 0) {
            if (bpf_map_delete_elem(fds->rules_fd, &key) == 0) {
                deleted = 1;
            }
        }
        if (ctx && ctx->db && ctx->db->is_open) {
            if (database_delete_rule_by_tuple(ctx->db, ip_str, (uint16_t)port, (uint8_t)proto) == 0) {
                deleted = 1;
            }
        }

        if (!deleted) {
            return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Rule not found");
        }
        return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"Rule deleted\"}");
    }

    // Numeric rule ID fallback
    int db_id = atoi(id_str);
    if (db_id > 0 && ctx && ctx->db && ctx->db->is_open) {
        struct rule_record rec;
        if (database_get_rule(ctx->db, db_id, &rec) == 0) {
            struct rule_key_t key = {0};
            if (fds && fds->rules_fd >= 0 && inet_pton(AF_INET, rec.ip_address, &key.ip) == 1) {
                key.port = htons(rec.port_start);
                key.proto = rec.protocol;
                bpf_map_delete_elem(fds->rules_fd, &key);
            }
            database_delete_rule(ctx->db, db_id);
            return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"Rule deleted\"}");
        }
    }

    return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Rule not found");
}
