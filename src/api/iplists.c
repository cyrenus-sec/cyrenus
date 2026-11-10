#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <bpf/bpf.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/database.h"
#include "../../include/common.h"

static int get_target_list_fd(struct api_context *ctx, const char *list_type) {
    if (!ctx || !ctx->fds || !list_type) return -1;
    if (strcmp(list_type, "whitelist") == 0) return ctx->fds->ip_whitelist_fd;
    if (strcmp(list_type, "blacklist") == 0) return ctx->fds->ip_blacklist_fd;
    return -1;
}

// Handler: GET /api/v1/iplists/:type
enum MHD_Result api_iplists_get(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *list_type) {
    if (!list_type || (strcmp(list_type, "whitelist") != 0 && strcmp(list_type, "blacklist") != 0)) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "List type must be 'whitelist' or 'blacklist'");
    }

    struct json_object *json_lists = json_object_new_array();
    if (ctx && ctx->db && ctx->db->is_open) {
        struct ip_list_record *entries = NULL;
        int count = 0;
        int rc = (strcmp(list_type, "whitelist") == 0)
                     ? database_list_whitelist(ctx->db, &entries, &count)
                     : database_list_blacklist(ctx->db, &entries, &count);

        if (rc == 0 && entries) {
            for (int i = 0; i < count; i++) {
                struct json_object *item = json_object_new_object();
                json_object_object_add(item, "id", json_object_new_int(entries[i].id));
                json_object_object_add(item, "ip_address", json_object_new_string(entries[i].ip_address));
                json_object_object_add(item, "cidr_range", json_object_new_int(entries[i].cidr_range));
                json_object_object_add(item, "list_type", json_object_new_string(entries[i].list_type));
                json_object_object_add(item, "reason", json_object_new_string(entries[i].reason));
                json_object_object_add(item, "expires_at", json_object_new_int64((int64_t)entries[i].expires_at));
                json_object_object_add(item, "created_at", json_object_new_int64((int64_t)entries[i].created_at));
                json_object_array_add(json_lists, item);
            }
            database_free_ip_list(entries, count);
        }
    }

    const char *json_str = json_object_to_json_string(json_lists);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(json_lists);
    return ret;
}

// Handler: POST /api/v1/iplists
enum MHD_Result api_iplists_add(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *upload_data, size_t size) {
    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    json_object *j_ip = NULL, *j_type = NULL, *j_cidr = NULL, *j_reason = NULL, *j_ttl = NULL, *j_expires = NULL;
    const char *raw_ip = NULL;
    if (json_object_object_get_ex(root, "ip_address", &j_ip) ||
        json_object_object_get_ex(root, "ip", &j_ip)) {
        raw_ip = json_object_get_string(j_ip);
    }

    const char *list_type = NULL;
    if (json_object_object_get_ex(root, "list_type", &j_type)) {
        list_type = json_object_get_string(j_type);
    }
    if (!list_type || (strcmp(list_type, "whitelist") != 0 && strcmp(list_type, "blacklist") != 0)) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "list_type must be 'whitelist' or 'blacklist'");
    }

    int explicit_cidr = -1;
    if (json_object_object_get_ex(root, "cidr_range", &j_cidr)) {
        explicit_cidr = json_object_get_int(j_cidr);
    }

    char canonical_ip[46] = {0};
    uint8_t cidr_val = 0;
    struct cyrenus_ip masked_ip = {0};
    int af = AF_INET;
    if (cyrenus_parse_cidr(raw_ip, explicit_cidr, canonical_ip, &cidr_val, &masked_ip, &af) != 0) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid IPv4/IPv6 address or CIDR range");
    }

    const char *reason = "";
    if (json_object_object_get_ex(root, "reason", &j_reason)) {
        const char *r = json_object_get_string(j_reason);
        if (r) reason = r;
    }

    time_t expires_at = 0;
    if (json_object_object_get_ex(root, "ttl_sec", &j_ttl)) {
        int64_t ttl = json_object_get_int64(j_ttl);
        if (ttl > 0) expires_at = time(NULL) + (time_t)ttl;
    } else if (json_object_object_get_ex(root, "expires_at", &j_expires)) {
        int64_t exp = json_object_get_int64(j_expires);
        if (exp > 0) expires_at = (time_t)exp;
    }

    // Update BPF LPM map if attached
    int map_fd = get_target_list_fd(ctx, list_type);
    if (map_fd >= 0) {
        struct ip_list_key key = {
            .prefixlen = cyrenus_ip_to_lpm_prefix(af, cidr_val),
            .ip = masked_ip
        };
        uint8_t val = 1;
        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
            json_object_put(root);
            return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to update BPF IP list map");
        }

        // Adding a host (/32 v4 or /128 v6) to whitelist should immediately lift any active auto-block
        bool is_single_host = (af == AF_INET && cidr_val == 32) || (af == AF_INET6 && cidr_val == 128);
        if (strcmp(list_type, "whitelist") == 0 && is_single_host &&
            ctx->fds && ctx->fds->auto_block_fd >= 0) {
            bpf_map_delete_elem(ctx->fds->auto_block_fd, &masked_ip);
        }
    }

    int new_id = 0;
    if (ctx && ctx->db && ctx->db->is_open) {
        struct ip_list_record rec = {0};
        snprintf(rec.ip_address, sizeof(rec.ip_address), "%s", canonical_ip);
        rec.cidr_range = cidr_val;
        snprintf(rec.list_type, sizeof(rec.list_type), "%s", list_type);
        snprintf(rec.reason, sizeof(rec.reason), "%s", reason);
        rec.expires_at = expires_at;
        if (database_insert_ip_list_ex(ctx->db, &rec, &new_id) != 0) {
            json_object_put(root);
            return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to persist IP list entry");
        }
    }

    json_object_put(root);

    struct json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "status", json_object_new_string("IP added to list"));
    json_object_object_add(j_resp, "id", json_object_new_int(new_id));
    json_object_object_add(j_resp, "ip_address", json_object_new_string(canonical_ip));
    json_object_object_add(j_resp, "cidr_range", json_object_new_int(cidr_val));
    json_object_object_add(j_resp, "list_type", json_object_new_string(list_type));

    const char *json_str = json_object_to_json_string(j_resp);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_resp);
    return ret;
}

// Handler: DELETE /api/v1/iplists/:id
enum MHD_Result api_iplists_delete(struct MHD_Connection *connection,
                                   struct api_context *ctx,
                                   int id) {
    if (id <= 0 || !ctx || !ctx->db || !ctx->db->is_open) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid IP list entry ID");
    }

    struct ip_list_record entry;
    if (database_get_ip_list_by_id(ctx->db, id, &entry) != 0) {
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "IP list entry not found");
    }

    int map_fd = get_target_list_fd(ctx, entry.list_type);
    if (map_fd >= 0) {
        char canonical_ip[46] = {0};
        uint8_t cidr_val = 0;
        struct cyrenus_ip masked_ip = {0};
        int af = AF_INET;
        int explicit_cidr = (entry.cidr_range > 0) ? (int)entry.cidr_range : -1;
        if (cyrenus_parse_cidr(entry.ip_address, explicit_cidr, canonical_ip, &cidr_val, &masked_ip, &af) == 0) {
            struct ip_list_key key = {
                .prefixlen = cyrenus_ip_to_lpm_prefix(af, cidr_val),
                .ip = masked_ip
            };
            bpf_map_delete_elem(map_fd, &key);
        }
    }

    if (database_delete_ip_list(ctx->db, id) != 0) {
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to delete IP list entry");
    }

    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"IP removed from list\"}");
}
