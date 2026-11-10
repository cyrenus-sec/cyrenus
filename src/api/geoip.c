#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../../include/api_handlers.h"
#include "../../include/geoip_helpers.h"
#include "../../include/database.h"
#include <json-c/json.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

static int normalize_country_code(const char *in, char out[3]) {
    if (!in || strlen(in) != 2) return -1;
    if (!isalpha((unsigned char)in[0]) || !isalpha((unsigned char)in[1])) return -1;
    out[0] = (char)toupper((unsigned char)in[0]);
    out[1] = (char)toupper((unsigned char)in[1]);
    out[2] = '\0';
    return 0;
}

// Handler: GET /api/v1/geoip/lookup/:ip
enum MHD_Result api_geoip_lookup(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *ip_str) {
    (void)ctx;
    if (!ip_str || ip_str[0] == '\0') {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing IP");
    }

    struct geoip_info info;
    if (geoip_lookup(ip_str, &info) == 0) {
        struct json_object *json_info = json_object_new_object();
        json_object_object_add(json_info, "ip", json_object_new_string(ip_str));
        json_object_object_add(json_info, "country_code", json_object_new_string(info.country_code));
        json_object_object_add(json_info, "country_name", json_object_new_string(info.country_name));
        json_object_object_add(json_info, "city", json_object_new_string(info.city));

        const char *json_str = json_object_to_json_string(json_info);
        enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
        json_object_put(json_info);
        return ret;
    }

    return api_send_error(connection, MHD_HTTP_NOT_FOUND, "GeoIP database unavailable or IP not found");
}

// Handler: GET /api/v1/geoip/rules
enum MHD_Result api_geoip_list_rules(struct MHD_Connection *connection, struct api_context *ctx) {
    struct json_object *j_arr = json_object_new_array();

    if (ctx && ctx->db && ctx->db->is_open) {
        struct geo_rule_record *rules = NULL;
        int count = 0;
        if (database_list_geo_rules(ctx->db, &rules, &count) == 0 && rules) {
            for (int i = 0; i < count; i++) {
                struct json_object *obj = json_object_new_object();
                json_object_object_add(obj, "id", json_object_new_int(rules[i].id));
                json_object_object_add(obj, "country_code", json_object_new_string(rules[i].country_code));
                json_object_object_add(obj, "action", json_object_new_string(rules[i].action[0] ? rules[i].action : "block"));
                json_object_object_add(obj, "priority", json_object_new_int(rules[i].priority));
                json_object_object_add(obj, "created_at", json_object_new_int64((int64_t)rules[i].created_at));
                json_object_array_add(j_arr, obj);
            }
            database_free_geo_rule_list(rules, count);
        }
    } else if (ctx && ctx->fds && ctx->fds->blocked_countries_fd >= 0) {
        uint16_t key = 0, next_key = 0;
        uint8_t val = 0;
        void *cur_key = NULL;
        while (bpf_map_get_next_key(ctx->fds->blocked_countries_fd, cur_key, &next_key) == 0) {
            if (bpf_map_lookup_elem(ctx->fds->blocked_countries_fd, &next_key, &val) == 0 && val == 1) {
                char code[3] = {(char)((next_key >> 8) & 0xFF), (char)(next_key & 0xFF), '\0'};
                struct json_object *obj = json_object_new_object();
                json_object_object_add(obj, "country_code", json_object_new_string(code));
                json_object_object_add(obj, "action", json_object_new_string("block"));
                json_object_array_add(j_arr, obj);
            }
            key = next_key;
            cur_key = &key;
        }
    }

    const char *json_str = json_object_to_json_string(j_arr);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_arr);
    return ret;
}

// Handler: POST /api/v1/geoip/rules
enum MHD_Result api_geoip_add_rule(struct MHD_Connection *connection, struct api_context *ctx,
                                   const char *upload_data, size_t size) {
    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    struct json_object *country_code_obj = NULL;
    if (!json_object_object_get_ex(root, "country_code", &country_code_obj)) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing country_code");
    }

    char code[3] = {0};
    if (normalize_country_code(json_object_get_string(country_code_obj), code) != 0) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid 2-letter ISO country code");
    }

    if (ctx && ctx->fds && ctx->fds->blocked_countries_fd >= 0) {
        uint16_t key = (uint16_t)(((unsigned char)code[0] << 8) | (unsigned char)code[1]);
        uint8_t value = 1; // DROP
        if (bpf_map_update_elem(ctx->fds->blocked_countries_fd, &key, &value, BPF_ANY) != 0) {
            json_object_put(root);
            return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to update BPF GeoIP map");
        }
    }

    if (ctx && ctx->db && ctx->db->is_open) {
        struct geo_rule_record rec = {0};
        snprintf(rec.country_code, sizeof(rec.country_code), "%s", code);
        snprintf(rec.action, sizeof(rec.action), "block");
        rec.priority = 1;
        database_insert_geo_rule(ctx->db, &rec);
    }

    json_object_put(root);
    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"blocked\"}");
}

// Handler: DELETE /api/v1/geoip/rules/:code
enum MHD_Result api_geoip_delete_rule(struct MHD_Connection *connection, struct api_context *ctx,
                                      const char *id_str) {
    char code[3] = {0};
    if (normalize_country_code(id_str, code) != 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid 2-letter ISO country code");
    }

    int deleted = 0;
    if (ctx && ctx->fds && ctx->fds->blocked_countries_fd >= 0) {
        uint16_t key = (uint16_t)(((unsigned char)code[0] << 8) | (unsigned char)code[1]);
        if (bpf_map_delete_elem(ctx->fds->blocked_countries_fd, &key) == 0) {
            deleted = 1;
        }
    }

    if (ctx && ctx->db && ctx->db->is_open) {
        if (database_delete_geo_rule_by_code(ctx->db, code) == 0) {
            deleted = 1;
        }
    }

    if (!deleted && ctx && ctx->fds && ctx->fds->blocked_countries_fd >= 0) {
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "GeoIP rule not found");
    }

    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"unblocked\"}");
}
