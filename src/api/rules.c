#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/database.h"
#include "../../include/common.h"

static void url_decode_str(const char *src, char *dst, size_t dst_len) {
    if (!dst || dst_len == 0) return;
    dst[0] = '\0';
    if (!src) return;
    size_t i = 0;
    while (*src && i + 1 < dst_len) {
        if (src[0] == '%' &&
            isxdigit((unsigned char)src[1]) &&
            isxdigit((unsigned char)src[2])) {
            char hex[3] = { src[1], src[2], '\0' };
            dst[i++] = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            dst[i++] = *src++;
        }
    }
    dst[i] = '\0';
}

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
    if (strcasecmp(proto, "icmpv6") == 0 || strcasecmp(proto, "icmp6") == 0 || strcmp(proto, "58") == 0) {
        *out = IPPROTO_ICMPV6;
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
        char rule_key[80];
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
                char ip_str[INET6_ADDRSTRLEN] = {0};
                cyrenus_ip_to_str(&next_key.ip, ip_str, sizeof(ip_str));
                uint16_t port_host = ntohs(next_key.port);

                int exists_in_db = 0;
                for (int i = 0; i < db_count; i++) {
                    struct cyrenus_ip db_ip = {0};
                    if (cyrenus_str_to_ip(db_rules[i].ip_address, &db_ip, NULL) == 0 &&
                        cyrenus_ip_equals(&db_ip, &next_key.ip) &&
                        db_rules[i].port_start == port_host &&
                        db_rules[i].protocol == next_key.proto) {
                        exists_in_db = 1;
                        break;
                    }
                }

                if (!exists_in_db) {
                    char rule_key[80];
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
    if (!ip_str || cyrenus_str_to_ip(ip_str, &key.ip, NULL) != 0) {
        json_object_put(json_rule);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid or missing IPv4/IPv6 address");
    }

    char canonical_ip[46] = {0};
    cyrenus_ip_to_str(&key.ip, canonical_ip, sizeof(canonical_ip));

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
            return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid protocol (use tcp, udp, icmp, icmpv6, or all)");
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
        // If allowing traffic for this IP, lift any active auto-block immediately
        if (rule.action == ACTION_PASS && fds->auto_block_fd >= 0) {
            bpf_map_delete_elem(fds->auto_block_fd, &key.ip);
        }
    }

    if (ctx && ctx->db && ctx->db->is_open) {
        struct rule_record rec = {0};
        snprintf(rec.ip_address, sizeof(rec.ip_address), "%s", canonical_ip);
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
    char decoded[128] = {0};
    url_decode_str(id_str, decoded, sizeof(decoded));

    if (decoded[0] == '\0') {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid rule ID");
    }

    // Parse "<ip>_<port>_<proto>" from right using strrchr so IPv6 colons never truncate
    char *last_us = strrchr(decoded, '_');
    if (last_us) {
        *last_us = '\0';
        char *prev_us = strrchr(decoded, '_');
        if (prev_us) {
            *prev_us = '\0';
            const char *ip_part = decoded;
            const char *port_part = prev_us + 1;
            const char *proto_part = last_us + 1;

            char *end1 = NULL, *end2 = NULL;
            long port = strtol(port_part, &end1, 10);
            long proto = strtol(proto_part, &end2, 10);

            if (port_part[0] && proto_part[0] &&
                end1 && *end1 == '\0' && end2 && *end2 == '\0' &&
                port >= 0 && port <= 65535 && proto >= 0 && proto <= 255) {

                struct rule_key_t key = {0};
                if (cyrenus_str_to_ip(ip_part, &key.ip, NULL) != 0) {
                    return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid IP address in rule ID");
                }
                char canonical_ip[46] = {0};
                cyrenus_ip_to_str(&key.ip, canonical_ip, sizeof(canonical_ip));

                key.port = htons((uint16_t)port);
                key.proto = (uint8_t)proto;

                int deleted = 0;
                if (fds && fds->rules_fd >= 0) {
                    if (bpf_map_delete_elem(fds->rules_fd, &key) == 0) {
                        deleted = 1;
                    }
                }
                if (ctx && ctx->db && ctx->db->is_open) {
                    if (database_delete_rule_by_tuple(ctx->db, canonical_ip, (uint16_t)port, (uint8_t)proto) == 0 ||
                        database_delete_rule_by_tuple(ctx->db, ip_part, (uint16_t)port, (uint8_t)proto) == 0) {
                        deleted = 1;
                    }
                }

                if (!deleted) {
                    return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Rule not found");
                }
                return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"Rule deleted\"}");
            }
        }
    }

    // Numeric rule ID fallback
    url_decode_str(id_str, decoded, sizeof(decoded));
    int db_id = atoi(decoded);
    if (db_id > 0 && ctx && ctx->db && ctx->db->is_open) {
        struct rule_record rec;
        if (database_get_rule(ctx->db, db_id, &rec) == 0) {
            struct rule_key_t key = {0};
            if (fds && fds->rules_fd >= 0 && cyrenus_str_to_ip(rec.ip_address, &key.ip, NULL) == 0) {
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
