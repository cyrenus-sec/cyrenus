#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <time.h>
#include <bpf/bpf.h>
#include <json-c/json.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/database.h"
#include "../../include/common.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME CLOCK_MONOTONIC
#endif

static void get_boottime_clock(uint64_t *now_ns_out, time_t *boot_unix_out) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_BOOTTIME, &ts);
    if (now_ns_out) {
        *now_ns_out = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    if (boot_unix_out) {
        *boot_unix_out = time(NULL) - ts.tv_sec;
    }
}

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

static int ci_contains(const char *haystack, const char *needle) {
    if (!needle || needle[0] == '\0') return 1;
    if (!haystack || haystack[0] == '\0') return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p != '\0'; p++) {
        size_t i = 0;
        while (i < nlen && p[i] != '\0' &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static const char *severity_to_label(int sev) {
    switch (sev) {
        case 4: return "critical";
        case 3: return "high";
        case 2: return "medium";
        default: return "low";
    }
}

struct merged_attack {
    char id_str[64];
    int64_t db_id;
    int64_t timestamp_unix;
    char time_str[32];
    char src_ip[46];
    struct cyrenus_ip src_ip_raw;
    uint8_t attack_id;
    char attack_type[64];
    char protocol[16];
    int severity;
    uint32_t packets;
    uint64_t bytes;
    uint32_t dropped_packets;
    uint64_t dropped_bytes;
    uint32_t peak_pps;
    int duration;
    bool blocked;
    char status[16];
};

static int cmp_merged_desc(const void *a, const void *b) {
    const struct merged_attack *ma = (const struct merged_attack *)a;
    const struct merged_attack *mb = (const struct merged_attack *)b;
    if (mb->timestamp_unix != ma->timestamp_unix) {
        return (mb->timestamp_unix > ma->timestamp_unix) ? 1 : -1;
    }
    return (mb->db_id > ma->db_id) ? 1 : ((mb->db_id < ma->db_id) ? -1 : 0);
}

static void format_unix_ts(time_t ts, char *buf, size_t len) {
    struct tm tm_buf;
    if (ts > 0 && localtime_r(&ts, &tm_buf)) {
        strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_buf);
    } else {
        snprintf(buf, len, "Unknown");
    }
}

// Handler: GET /api/v1/attacks
enum MHD_Result api_attacks_list(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *year, const char *month) {
    (void)year;
    (void)month;

    const char *status_filter = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "status");
    const char *type_filter = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "attack_type");
    if (!type_filter) {
        type_filter = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "type");
    }
    const char *search_filter = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "search");
    const char *limit_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
    const char *offset_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "offset");

    int limit = limit_str ? atoi(limit_str) : 50;
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;
    int offset = offset_str ? atoi(offset_str) : 0;
    if (offset < 0) offset = 0;

    uint64_t now_ns = 0;
    time_t boot_time = 0;
    get_boottime_clock(&now_ns, &boot_time);
    time_t now_unix = time(NULL);

    int capacity = 128;
    int total_items = 0;
    struct merged_attack *items = calloc((size_t)capacity, sizeof(struct merged_attack));
    if (!items) {
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Out of memory");
    }

    // 1. Collect live eBPF active attacks
    if (ctx && ctx->fds && ctx->fds->active_attacks_fd >= 0) {
        struct active_attack_entry *ebpf_entries = NULL;
        int ebpf_count = get_active_attacks(&ebpf_entries, ctx->fds->active_attacks_fd);

        for (int i = 0; i < ebpf_count; i++) {
            struct active_attack_key *k = &ebpf_entries[i].key;
            struct active_attack_val *v = &ebpf_entries[i].val;

            if (v->packets == 0) continue;

            bool currently_blocked = (v->blocked != 0);
            if (ctx->fds->auto_block_fd >= 0 && !cyrenus_ip_is_zero(&k->src_ip)) {
                struct auto_block_val ab;
                if (bpf_map_lookup_elem(ctx->fds->auto_block_fd, &k->src_ip, &ab) == 0) {
                    if (now_ns < ab.blocked_until_ns) {
                        currently_blocked = true;
                    }
                }
            }

            if (total_items >= capacity) {
                capacity *= 2;
                struct merged_attack *tmp = realloc(items, sizeof(struct merged_attack) * (size_t)capacity);
                if (!tmp) break;
                items = tmp;
            }

            struct merged_attack *m = &items[total_items++];
            memset(m, 0, sizeof(*m));

            m->db_id = 0;
            m->src_ip_raw = k->src_ip;
            m->attack_id = k->attack_id;

            char ip_hex[33];
            cyrenus_ip_to_hex(&k->src_ip, ip_hex);
            snprintf(m->id_str, sizeof(m->id_str), "ebpf_%s_%u", ip_hex, k->attack_id);
            cyrenus_ip_to_str(&k->src_ip, m->src_ip, sizeof(m->src_ip));

            time_t last_unix = boot_time + (time_t)(v->last_seen_ns / 1000000000ULL);
            if (last_unix > now_unix) last_unix = now_unix;
            m->timestamp_unix = last_unix;
            format_unix_ts(last_unix, m->time_str, sizeof(m->time_str));

            snprintf(m->attack_type, sizeof(m->attack_type), "%s", get_attack_name_by_id(k->attack_id));
            snprintf(m->protocol, sizeof(m->protocol), "%s", get_proto_name(v->protocol));
            m->severity = get_attack_severity(k->attack_id, v->peak_pps, v->packets);
            m->packets = v->packets;
            m->bytes = v->bytes;
            m->dropped_packets = v->dropped_packets;
            m->dropped_bytes = v->dropped_bytes;
            m->peak_pps = v->peak_pps;
            m->duration = (v->last_seen_ns >= v->first_seen_ns)
                              ? (int)((v->last_seen_ns - v->first_seen_ns) / 1000000000ULL)
                              : 0;
            if (m->duration < 1) m->duration = 1;
            m->blocked = currently_blocked;

            uint64_t age_ns = (now_ns > v->last_seen_ns) ? (now_ns - v->last_seen_ns) : 0;
            if (age_ns <= 30000000000ULL) {
                snprintf(m->status, sizeof(m->status), "active");
            } else if (m->dropped_packets > 0 || m->blocked) {
                snprintf(m->status, sizeof(m->status), "mitigated");
            } else {
                snprintf(m->status, sizeof(m->status), "resolved");
            }
        }
        if (ebpf_entries) free(ebpf_entries);
    }

    // 2. Merge SQLite attack history (deduplicating active incidents against live map)
    if (ctx && ctx->db && ctx->db->is_open) {
        struct attack_record *history = NULL;
        int history_count = 0;
        if (database_list_attacks(ctx->db, &history, &history_count, 500, 0) == 0 && history) {
            for (int i = 0; i < history_count; i++) {
                struct attack_record *h = &history[i];
                int merged = 0;

                for (int j = 0; j < total_items; j++) {
                    if (items[j].db_id == 0 &&
                        strcmp(items[j].src_ip, h->src_ip) == 0 &&
                        strcmp(items[j].attack_type, h->attack_type) == 0 &&
                        (strcmp(h->status, "active") == 0 ||
                         llabs((long long)items[j].timestamp_unix - (long long)h->timestamp) <= 120)) {
                        items[j].db_id = h->id;
                        snprintf(items[j].id_str, sizeof(items[j].id_str), "%lld", (long long)h->id);
                        if (strcmp(h->status, "resolved") == 0) {
                            snprintf(items[j].status, sizeof(items[j].status), "resolved");
                        }
                        if (h->packets > items[j].packets) items[j].packets = h->packets;
                        if (h->bytes > items[j].bytes) items[j].bytes = h->bytes;
                        if (h->dropped_packets > items[j].dropped_packets) items[j].dropped_packets = h->dropped_packets;
                        if (h->dropped_bytes > items[j].dropped_bytes) items[j].dropped_bytes = h->dropped_bytes;
                        if (h->peak_pps > items[j].peak_pps) items[j].peak_pps = h->peak_pps;
                        if (h->duration > items[j].duration) items[j].duration = h->duration;
                        merged = 1;
                        break;
                    }
                }

                if (!merged) {
                    if (total_items >= capacity) {
                        capacity *= 2;
                        struct merged_attack *tmp = realloc(items, sizeof(struct merged_attack) * (size_t)capacity);
                        if (!tmp) break;
                        items = tmp;
                    }
                    struct merged_attack *m = &items[total_items++];
                    memset(m, 0, sizeof(*m));
                    m->db_id = h->id;
                    snprintf(m->id_str, sizeof(m->id_str), "%lld", (long long)h->id);
                    m->timestamp_unix = h->timestamp;
                    format_unix_ts((time_t)h->timestamp, m->time_str, sizeof(m->time_str));
                    snprintf(m->src_ip, sizeof(m->src_ip), "%s", h->src_ip);
                    snprintf(m->attack_type, sizeof(m->attack_type), "%s", h->attack_type);
                    snprintf(m->protocol, sizeof(m->protocol), "%s", h->protocol[0] ? h->protocol : "UNKNOWN");
                    m->severity = h->severity > 0 ? h->severity : 2;
                    m->packets = h->packets;
                    m->bytes = h->bytes;
                    m->dropped_packets = h->dropped_packets;
                    m->dropped_bytes = h->dropped_bytes;
                    m->peak_pps = h->peak_pps;
                    m->duration = h->duration;
                    m->blocked = h->blocked;
                    snprintf(m->status, sizeof(m->status), "%s", h->status[0] ? h->status : "mitigated");
                }
            }
            database_free_attack_list(history, history_count);
        }
    }

    if (total_items > 1) {
        qsort(items, (size_t)total_items, sizeof(struct merged_attack), cmp_merged_desc);
    }

    // 3. Summary counts across all items
    int count_active = 0, count_mitigated = 0, count_resolved = 0;
    struct json_object *j_by_type = json_object_new_object();
    for (int i = 0; i < total_items; i++) {
        if (strcmp(items[i].status, "active") == 0) count_active++;
        else if (strcmp(items[i].status, "mitigated") == 0) count_mitigated++;
        else count_resolved++;

        struct json_object *existing = NULL;
        int cur = 0;
        if (json_object_object_get_ex(j_by_type, items[i].attack_type, &existing)) {
            cur = json_object_get_int(existing);
        }
        json_object_object_add(j_by_type, items[i].attack_type, json_object_new_int(cur + 1));
    }

    // 4. Filter & paginate
    struct json_object *j_attacks = json_object_new_array();
    int filtered_total = 0;

    for (int i = 0; i < total_items; i++) {
        struct merged_attack *m = &items[i];

        if (status_filter && status_filter[0] && strcasecmp(status_filter, "all") != 0) {
            if (strcasecmp(m->status, status_filter) != 0) continue;
        }
        if (type_filter && type_filter[0] && strcasecmp(type_filter, "all") != 0) {
            if (!ci_contains(m->attack_type, type_filter)) continue;
        }
        if (search_filter && search_filter[0]) {
            if (!ci_contains(m->src_ip, search_filter) &&
                !ci_contains(m->attack_type, search_filter) &&
                !ci_contains(m->protocol, search_filter)) {
                continue;
            }
        }

        if (filtered_total >= offset && json_object_array_length(j_attacks) < limit) {
            struct json_object *obj = json_object_new_object();
            if (m->db_id > 0) {
                json_object_object_add(obj, "id", json_object_new_int64(m->db_id));
            } else {
                json_object_object_add(obj, "id", json_object_new_string(m->id_str));
            }
            json_object_object_add(obj, "timestamp", json_object_new_string(m->time_str));
            json_object_object_add(obj, "unix_timestamp", json_object_new_int64(m->timestamp_unix));
            json_object_object_add(obj, "src_ip", json_object_new_string(m->src_ip));
            json_object_object_add(obj, "attack_type", json_object_new_string(m->attack_type));
            json_object_object_add(obj, "protocol", json_object_new_string(m->protocol));
            json_object_object_add(obj, "severity", json_object_new_int(m->severity));
            json_object_object_add(obj, "severity_label", json_object_new_string(severity_to_label(m->severity)));
            json_object_object_add(obj, "packets", json_object_new_int64((int64_t)m->packets));
            json_object_object_add(obj, "bytes", json_object_new_int64((int64_t)m->bytes));
            json_object_object_add(obj, "dropped_packets", json_object_new_int64((int64_t)m->dropped_packets));
            json_object_object_add(obj, "dropped_bytes", json_object_new_int64((int64_t)m->dropped_bytes));
            json_object_object_add(obj, "peak_pps", json_object_new_int64((int64_t)m->peak_pps));
            json_object_object_add(obj, "duration", json_object_new_int(m->duration));
            json_object_object_add(obj, "blocked", json_object_new_boolean(m->blocked));
            json_object_object_add(obj, "status", json_object_new_string(m->status));
            json_object_array_add(j_attacks, obj);
        }
        filtered_total++;
    }

    free(items);

    struct json_object *j_summary = json_object_new_object();
    json_object_object_add(j_summary, "total", json_object_new_int(total_items));
    json_object_object_add(j_summary, "active", json_object_new_int(count_active));
    json_object_object_add(j_summary, "mitigated", json_object_new_int(count_mitigated));
    json_object_object_add(j_summary, "resolved", json_object_new_int(count_resolved));
    json_object_object_add(j_summary, "by_type", j_by_type);

    struct json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "attacks", j_attacks);
    json_object_object_add(j_resp, "total", json_object_new_int(filtered_total));
    json_object_object_add(j_resp, "limit", json_object_new_int(limit));
    json_object_object_add(j_resp, "offset", json_object_new_int(offset));
    json_object_object_add(j_resp, "summary", j_summary);

    const char *json_str = json_object_to_json_string(j_resp);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_resp);
    return ret;
}

// Handler: GET /api/v1/attacks/:id
enum MHD_Result api_attacks_get(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                int id) {
    if (!ctx || !ctx->db || !ctx->db->is_open || id <= 0) {
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Attack not found");
    }

    struct attack_record rec;
    if (database_get_attack(ctx->db, (int64_t)id, &rec) != 0) {
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Attack not found");
    }

    char time_str[32];
    format_unix_ts((time_t)rec.timestamp, time_str, sizeof(time_str));

    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "id", json_object_new_int64(rec.id));
    json_object_object_add(obj, "timestamp", json_object_new_string(time_str));
    json_object_object_add(obj, "unix_timestamp", json_object_new_int64(rec.timestamp));
    json_object_object_add(obj, "src_ip", json_object_new_string(rec.src_ip));
    json_object_object_add(obj, "attack_type", json_object_new_string(rec.attack_type));
    json_object_object_add(obj, "protocol", json_object_new_string(rec.protocol));
    json_object_object_add(obj, "severity", json_object_new_int(rec.severity));
    json_object_object_add(obj, "severity_label", json_object_new_string(severity_to_label(rec.severity)));
    json_object_object_add(obj, "packets", json_object_new_int64((int64_t)rec.packets));
    json_object_object_add(obj, "bytes", json_object_new_int64((int64_t)rec.bytes));
    json_object_object_add(obj, "dropped_packets", json_object_new_int64((int64_t)rec.dropped_packets));
    json_object_object_add(obj, "dropped_bytes", json_object_new_int64((int64_t)rec.dropped_bytes));
    json_object_object_add(obj, "peak_pps", json_object_new_int64((int64_t)rec.peak_pps));
    json_object_object_add(obj, "duration", json_object_new_int(rec.duration));
    json_object_object_add(obj, "blocked", json_object_new_boolean(rec.blocked));
    json_object_object_add(obj, "status", json_object_new_string(rec.status));

    const char *json_str = json_object_to_json_string(obj);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(obj);
    return ret;
}

// Handler: POST /api/v1/attacks/:id/resolve
enum MHD_Result api_attacks_resolve(struct MHD_Connection *connection,
                                    struct api_context *ctx,
                                    const char *id_str) {
    if (!id_str || id_str[0] == '\0') {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing attack ID");
    }

    int updated = 0;
    if (strncmp(id_str, "ebpf_", 5) == 0) {
        const char *rest = id_str + 5;
        const char *sep = strrchr(rest, '_');
        if (sep && (sep - rest) == 32 && ctx && ctx->fds && ctx->fds->active_attacks_fd >= 0) {
            char hex[33];
            memcpy(hex, rest, 32);
            hex[32] = '\0';
            unsigned int atk_id = (unsigned int)atoi(sep + 1);
            struct active_attack_key akey = {0};
            if (atk_id > 0 && atk_id <= ATK_ID_MAX && cyrenus_hex_to_ip(hex, &akey.src_ip) == 0) {
                akey.attack_id = (uint8_t)atk_id;
                if (bpf_map_delete_elem(ctx->fds->active_attacks_fd, &akey) == 0) {
                    updated = 1;
                }
            }
        }
    } else {
        int64_t db_id = atoll(id_str);
        if (db_id > 0 && ctx && ctx->db && ctx->db->is_open) {
            struct attack_record rec;
            if (database_get_attack(ctx->db, db_id, &rec) == 0) {
                if (database_update_attack_status(ctx->db, db_id, "resolved") == 0) {
                    updated = 1;
                }
                if (ctx->fds && ctx->fds->active_attacks_fd >= 0) {
                    for (uint8_t aid = 1; aid <= ATK_ID_MAX; aid++) {
                        if (strcmp(get_attack_name_by_id(aid), rec.attack_type) == 0) {
                            struct active_attack_key akey = {0};
                            akey.attack_id = aid;
                            if ((aid == ATK_ID_GLOBAL_SYN_FLOOD || aid == ATK_ID_GLOBAL_UDP_FLOOD) &&
                                strcmp(rec.src_ip, "0.0.0.0") == 0) {
                                memset(&akey.src_ip, 0, sizeof(akey.src_ip));
                                bpf_map_delete_elem(ctx->fds->active_attacks_fd, &akey);
                            } else if (cyrenus_str_to_ip(rec.src_ip, &akey.src_ip, NULL) == 0) {
                                bpf_map_delete_elem(ctx->fds->active_attacks_fd, &akey);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    if (!updated) {
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Attack record not found");
    }

    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"resolved\"}");
}

// Handler: DELETE /api/v1/attacks
enum MHD_Result api_attacks_clear(struct MHD_Connection *connection,
                                  struct api_context *ctx) {
    if (ctx && ctx->db && ctx->db->is_open) {
        database_delete_all_attacks(ctx->db);
    }

    if (ctx && ctx->fds && ctx->fds->active_attacks_fd >= 0) {
        struct active_attack_key key = {0}, next_key = {0};
        void *cur = NULL;
        struct active_attack_key to_del[256];
        int n = 0;
        while (bpf_map_get_next_key(ctx->fds->active_attacks_fd, cur, &next_key) == 0) {
            if (n < 256) to_del[n++] = next_key;
            key = next_key;
            cur = &key;
        }
        for (int i = 0; i < n; i++) {
            bpf_map_delete_elem(ctx->fds->active_attacks_fd, &to_del[i]);
        }
    }

    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"cleared\"}");
}

// Handler: GET /api/v1/blocks
enum MHD_Result api_blocks_list(struct MHD_Connection *connection,
                                struct api_context *ctx) {
    struct json_object *j_blocks = json_object_new_array();

    if (ctx && ctx->fds && ctx->fds->auto_block_fd >= 0) {
        uint64_t now_ns = 0;
        time_t boot_time = 0;
        get_boottime_clock(&now_ns, &boot_time);

        struct cyrenus_ip key = {0}, next_key = {0};
        void *cur = NULL;
        struct auto_block_val val;

        while (bpf_map_get_next_key(ctx->fds->auto_block_fd, cur, &next_key) == 0) {
            if (bpf_map_lookup_elem(ctx->fds->auto_block_fd, &next_key, &val) == 0) {
                if (now_ns < val.blocked_until_ns) {
                    char ip_str[INET6_ADDRSTRLEN] = {0};
                    cyrenus_ip_to_str(&next_key, ip_str, sizeof(ip_str));

                    uint64_t rem_sec = (val.blocked_until_ns - now_ns) / 1000000000ULL;
                    char first_str[32], last_str[32];
                    format_unix_ts(boot_time + (time_t)(val.first_seen_ns / 1000000000ULL), first_str, sizeof(first_str));
                    format_unix_ts(boot_time + (time_t)(val.last_seen_ns / 1000000000ULL), last_str, sizeof(last_str));

                    struct json_object *obj = json_object_new_object();
                    json_object_object_add(obj, "ip", json_object_new_string(ip_str));
                    json_object_object_add(obj, "attack_id", json_object_new_int(val.attack_id));
                    json_object_object_add(obj, "attack_type", json_object_new_string(get_attack_name_by_id(val.attack_id)));
                    json_object_object_add(obj, "protocol", json_object_new_string(get_proto_name(val.protocol)));
                    json_object_object_add(obj, "blocked_packets", json_object_new_int64((int64_t)val.blocked_packets));
                    json_object_object_add(obj, "blocked_bytes", json_object_new_int64((int64_t)val.blocked_bytes));
                    json_object_object_add(obj, "peak_pps", json_object_new_int64((int64_t)val.peak_pps));
                    json_object_object_add(obj, "remaining_sec", json_object_new_int64((int64_t)rem_sec));
                    json_object_object_add(obj, "first_seen", json_object_new_string(first_str));
                    json_object_object_add(obj, "last_seen", json_object_new_string(last_str));
                    json_object_array_add(j_blocks, obj);
                }
            }
            key = next_key;
            cur = &key;
        }
    }

    struct json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "blocks", j_blocks);
    json_object_object_add(j_resp, "total", json_object_new_int(json_object_array_length(j_blocks)));

    const char *json_str = json_object_to_json_string(j_resp);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_resp);
    return ret;
}

// Handler: DELETE /api/v1/blocks/:ip
enum MHD_Result api_blocks_delete(struct MHD_Connection *connection,
                                  struct api_context *ctx,
                                  const char *ip_str) {
    char decoded_ip[80] = {0};
    url_decode_str(ip_str, decoded_ip, sizeof(decoded_ip));

    struct cyrenus_ip target_ip = {0};
    if (decoded_ip[0] == '\0' || cyrenus_str_to_ip(decoded_ip, &target_ip, NULL) != 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid IP address");
    }

    int removed = 0;

    if (ctx && ctx->fds) {
        if (ctx->fds->auto_block_fd >= 0 && bpf_map_delete_elem(ctx->fds->auto_block_fd, &target_ip) == 0) {
            removed = 1;
        }
        if (ctx->fds->udp_flood_fd >= 0) bpf_map_delete_elem(ctx->fds->udp_flood_fd, &target_ip);
        if (ctx->fds->syn_flood_fd >= 0) bpf_map_delete_elem(ctx->fds->syn_flood_fd, &target_ip);
        if (ctx->fds->dns_track_fd >= 0) bpf_map_delete_elem(ctx->fds->dns_track_fd, &target_ip);
        if (ctx->fds->active_attacks_fd >= 0) {
            for (uint8_t aid = 1; aid <= ATK_ID_MAX; aid++) {
                struct active_attack_key akey = { .src_ip = target_ip, .attack_id = aid };
                struct active_attack_val aval;
                if (bpf_map_lookup_elem(ctx->fds->active_attacks_fd, &akey, &aval) == 0) {
                    aval.blocked = 0;
                    bpf_map_update_elem(ctx->fds->active_attacks_fd, &akey, &aval, BPF_ANY);
                }
            }
        }
    }

    if (!removed && ctx && ctx->fds && ctx->fds->auto_block_fd >= 0) {
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "IP is not currently auto-blocked");
    }

    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"unblocked\"}");
}
