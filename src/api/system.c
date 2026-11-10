#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/runtime_config.h"
#include "../../include/common.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME CLOCK_MONOTONIC
#endif

// Handler: GET /api/v1/system/health
enum MHD_Result api_system_health(struct MHD_Connection *connection,
                                  struct api_context *ctx) {
    (void)ctx;
    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"healthy\",\"version\":\"2.0.0\"}");
}

// Handler: GET /api/v1/system/stats
enum MHD_Result api_system_stats(struct MHD_Connection *connection,
                                 struct api_context *ctx) {
    struct json_object *j_stats = json_object_new_object();
    struct runtime_config *cfg = ctx ? ctx->config : NULL;

    time_t now = time(NULL);
    int64_t uptime_sec = (cfg && cfg->start_time > 0 && now >= cfg->start_time)
                             ? (int64_t)(now - cfg->start_time)
                             : 0;

    // Database file size & filesystem disk stats
    uint64_t db_size_bytes = 0;
    uint64_t disk_total_bytes = 0;
    uint64_t disk_free_bytes = 0;
    uint64_t disk_used_bytes = 0;

    if (cfg && cfg->database_path[0]) {
        struct stat st;
        if (stat(cfg->database_path, &st) == 0) {
            db_size_bytes = (uint64_t)st.st_size;
        }
        char dir_path[MAX_PATH_LEN];
        snprintf(dir_path, sizeof(dir_path), "%s", cfg->database_path);
        char *slash = strrchr(dir_path, '/');
        if (slash && slash != dir_path) *slash = '\0';
        else snprintf(dir_path, sizeof(dir_path), "/");

        struct statvfs vfs;
        if (statvfs(dir_path, &vfs) == 0 || statvfs("/", &vfs) == 0) {
            disk_total_bytes = (uint64_t)vfs.f_blocks * (uint64_t)vfs.f_frsize;
            disk_free_bytes = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
            uint64_t unavail = (uint64_t)vfs.f_bfree * (uint64_t)vfs.f_frsize;
            disk_used_bytes = (disk_total_bytes >= unavail) ? (disk_total_bytes - unavail) : 0;
        }
    }

    // Aggregate per-CPU BPF global_stats
    struct global_stats_t g_sum = {0};
    if (ctx && ctx->fds && ctx->fds->global_stats_fd >= 0) {
        int num_cpus = libbpf_num_possible_cpus();
        if (num_cpus > 0) {
            struct global_stats_t *per_cpu = calloc((size_t)num_cpus, sizeof(struct global_stats_t));
            if (per_cpu) {
                uint32_t key = 0;
                if (bpf_map_lookup_elem(ctx->fds->global_stats_fd, &key, per_cpu) == 0) {
                    for (int i = 0; i < num_cpus; i++) {
                        g_sum.total_packets += per_cpu[i].total_packets;
                        g_sum.total_bytes += per_cpu[i].total_bytes;
                        g_sum.passed_packets += per_cpu[i].passed_packets;
                        g_sum.passed_bytes += per_cpu[i].passed_bytes;
                        g_sum.dropped_packets += per_cpu[i].dropped_packets;
                        g_sum.dropped_bytes += per_cpu[i].dropped_bytes;
                        g_sum.udp_drops += per_cpu[i].udp_drops;
                        g_sum.syn_drops += per_cpu[i].syn_drops;
                        g_sum.icmp_drops += per_cpu[i].icmp_drops;
                        g_sum.dns_drops += per_cpu[i].dns_drops;
                        g_sum.frag_drops += per_cpu[i].frag_drops;
                        g_sum.rule_drops += per_cpu[i].rule_drops;
                        g_sum.geo_drops += per_cpu[i].geo_drops;
                        g_sum.autoblock_drops += per_cpu[i].autoblock_drops;
                    }
                }
                free(per_cpu);
            }
        }
    }

    // Count active blocks & active attacks
    struct timespec ts_boot = {0};
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    uint64_t now_ns = (uint64_t)ts_boot.tv_sec * 1000000000ULL + (uint64_t)ts_boot.tv_nsec;

    int active_blocks = 0;
    if (ctx && ctx->fds && ctx->fds->auto_block_fd >= 0) {
        uint32_t k = 0, nk = 0;
        void *cur = NULL;
        struct auto_block_val val;
        while (bpf_map_get_next_key(ctx->fds->auto_block_fd, cur, &nk) == 0) {
            if (bpf_map_lookup_elem(ctx->fds->auto_block_fd, &nk, &val) == 0 &&
                now_ns < val.blocked_until_ns) {
                active_blocks++;
            }
            k = nk;
            cur = &k;
        }
    }

    int active_attacks = 0;
    if (ctx && ctx->fds && ctx->fds->active_attacks_fd >= 0) {
        struct active_attack_key k = {0}, nk = {0};
        void *cur = NULL;
        struct active_attack_val val;
        while (bpf_map_get_next_key(ctx->fds->active_attacks_fd, cur, &nk) == 0) {
            if (bpf_map_lookup_elem(ctx->fds->active_attacks_fd, &nk, &val) == 0 &&
                val.packets > 0 && now_ns >= val.last_seen_ns &&
                (now_ns - val.last_seen_ns) <= 30000000000ULL) {
                active_attacks++;
            }
            k = nk;
            cur = &k;
        }
    }

    // Count DB entities
    int attacks_total = 0, rules_count = 0, whitelist_count = 0, blacklist_count = 0, geo_rules_count = 0;
    if (ctx && ctx->db && ctx->db->is_open) {
        database_count_attacks(ctx->db, &attacks_total);

        struct rule_record *rules = NULL;
        if (database_list_rules(ctx->db, &rules, &rules_count) == 0 && rules) {
            database_free_rule_list(rules, rules_count);
        }
        struct ip_list_record *wl = NULL, *bl = NULL;
        if (database_list_whitelist(ctx->db, &wl, &whitelist_count) == 0 && wl) {
            database_free_ip_list(wl, whitelist_count);
        }
        if (database_list_blacklist(ctx->db, &bl, &blacklist_count) == 0 && bl) {
            database_free_ip_list(bl, blacklist_count);
        }
        struct geo_rule_record *gr = NULL;
        if (database_list_geo_rules(ctx->db, &gr, &geo_rules_count) == 0 && gr) {
            database_free_geo_rule_list(gr, geo_rules_count);
        }
    }

    json_object_object_add(j_stats, "uptime_sec", json_object_new_int64(uptime_sec));
    json_object_object_add(j_stats, "interface", json_object_new_string(cfg ? cfg->interface : ""));
    json_object_object_add(j_stats, "xdp_mode", json_object_new_string(cfg ? cfg->xdp_mode : "Unknown"));
    json_object_object_add(j_stats, "dry_run", json_object_new_boolean(cfg ? cfg->dry_run : false));
    json_object_object_add(j_stats, "http_port", json_object_new_int(cfg ? cfg->http_port : 8181));
    json_object_object_add(j_stats, "ws_port", json_object_new_int(cfg ? cfg->http_port + 1 : 8182));
    json_object_object_add(j_stats, "geoip_enabled",
                           json_object_new_boolean(cfg && !cfg->no_geoip && cfg->geoip_db_path[0] != '\0'));
    json_object_object_add(j_stats, "db_size_bytes", json_object_new_int64((int64_t)db_size_bytes));
    json_object_object_add(j_stats, "disk_total_bytes", json_object_new_int64((int64_t)disk_total_bytes));
    json_object_object_add(j_stats, "disk_free_bytes", json_object_new_int64((int64_t)disk_free_bytes));
    json_object_object_add(j_stats, "disk_used_bytes", json_object_new_int64((int64_t)disk_used_bytes));
    json_object_object_add(j_stats, "attacks_total", json_object_new_int(attacks_total));
    json_object_object_add(j_stats, "active_attacks", json_object_new_int(active_attacks));
    json_object_object_add(j_stats, "active_blocks", json_object_new_int(active_blocks));
    json_object_object_add(j_stats, "rules_count", json_object_new_int(rules_count));
    json_object_object_add(j_stats, "whitelist_count", json_object_new_int(whitelist_count));
    json_object_object_add(j_stats, "blacklist_count", json_object_new_int(blacklist_count));
    json_object_object_add(j_stats, "geo_rules_count", json_object_new_int(geo_rules_count));

    struct json_object *j_global = json_object_new_object();
    json_object_object_add(j_global, "total_packets", json_object_new_int64((int64_t)g_sum.total_packets));
    json_object_object_add(j_global, "total_bytes", json_object_new_int64((int64_t)g_sum.total_bytes));
    json_object_object_add(j_global, "passed_packets", json_object_new_int64((int64_t)g_sum.passed_packets));
    json_object_object_add(j_global, "passed_bytes", json_object_new_int64((int64_t)g_sum.passed_bytes));
    json_object_object_add(j_global, "dropped_packets", json_object_new_int64((int64_t)g_sum.dropped_packets));
    json_object_object_add(j_global, "dropped_bytes", json_object_new_int64((int64_t)g_sum.dropped_bytes));
    json_object_object_add(j_global, "udp_drops", json_object_new_int64((int64_t)g_sum.udp_drops));
    json_object_object_add(j_global, "syn_drops", json_object_new_int64((int64_t)g_sum.syn_drops));
    json_object_object_add(j_global, "icmp_drops", json_object_new_int64((int64_t)g_sum.icmp_drops));
    json_object_object_add(j_global, "dns_drops", json_object_new_int64((int64_t)g_sum.dns_drops));
    json_object_object_add(j_global, "frag_drops", json_object_new_int64((int64_t)g_sum.frag_drops));
    json_object_object_add(j_global, "rule_drops", json_object_new_int64((int64_t)g_sum.rule_drops));
    json_object_object_add(j_global, "geo_drops", json_object_new_int64((int64_t)g_sum.geo_drops));
    json_object_object_add(j_global, "autoblock_drops", json_object_new_int64((int64_t)g_sum.autoblock_drops));
    json_object_object_add(j_stats, "global_stats", j_global);

    const char *json_str = json_object_to_json_string(j_stats);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_stats);
    return ret;
}

// Handler: GET /api/v1/system/settings
enum MHD_Result api_system_get_settings(struct MHD_Connection *connection,
                                        struct api_context *ctx) {
    json_object *j_settings = json_object_new_object();

    if (ctx && ctx->config) {
        json_object_object_add(j_settings, "interface", json_object_new_string(ctx->config->interface));
        json_object_object_add(j_settings, "xdp_mode", json_object_new_string(ctx->config->xdp_mode));
        json_object_object_add(j_settings, "dry_run", json_object_new_boolean(ctx->config->dry_run));
        json_object_object_add(j_settings, "http_port", json_object_new_int(ctx->config->http_port));
        json_object_object_add(j_settings, "ws_port", json_object_new_int(ctx->config->http_port + 1));
        json_object_object_add(j_settings, "log_level", json_object_new_int(ctx->config->log_level));
        json_object_object_add(j_settings, "geoip_enabled",
            json_object_new_boolean(!ctx->config->no_geoip && ctx->config->geoip_db_path[0] != '\0'));

        // Thresholds & Auto-Mitigation
        json_object_object_add(j_settings, "syn_flood_rate", json_object_new_int64((int64_t)ctx->config->syn_flood_rate));
        json_object_object_add(j_settings, "udp_flood_rate", json_object_new_int64((int64_t)ctx->config->udp_flood_rate));
        json_object_object_add(j_settings, "icmp_flood_rate", json_object_new_int64((int64_t)ctx->config->icmp_flood_rate));
        json_object_object_add(j_settings, "dns_amp_rate", json_object_new_int64((int64_t)ctx->config->dns_amp_rate));
        json_object_object_add(j_settings, "max_frags", json_object_new_int64((int64_t)ctx->config->max_frags));
        json_object_object_add(j_settings, "auto_block_enabled", json_object_new_boolean(ctx->config->auto_block_enabled != 0));
        json_object_object_add(j_settings, "auto_block_duration_sec", json_object_new_int64((int64_t)ctx->config->auto_block_duration_sec));
        json_object_object_add(j_settings, "global_syn_rate", json_object_new_int64((int64_t)ctx->config->global_syn_rate));
        json_object_object_add(j_settings, "global_udp_rate", json_object_new_int64((int64_t)ctx->config->global_udp_rate));
        json_object_object_add(j_settings, "max_dns_response_size", json_object_new_int64((int64_t)ctx->config->max_dns_response_size));
    }

    const char *json_str = json_object_to_json_string(j_settings);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_settings);
    return ret;
}

static void persist_u32_setting(struct database *db, const char *key, uint32_t val) {
    if (!db || !db->is_open) return;
    char buf[32];
    snprintf(buf, sizeof(buf), "%u", val);
    database_set_config(db, key, buf);
}

// Handler: POST /api/v1/system/settings
enum MHD_Result api_system_update_settings(struct MHD_Connection *connection,
                                           struct api_context *ctx,
                                           const char *upload_data, size_t size) {
    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    struct runtime_config next = *ctx->config;
    struct json_object *j_val = NULL;

    if (json_object_object_get_ex(root, "syn_flood_rate", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 1 || v > 10000000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "syn_flood_rate must be 1..10000000"); }
        next.syn_flood_rate = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "udp_flood_rate", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 1 || v > 10000000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "udp_flood_rate must be 1..10000000"); }
        next.udp_flood_rate = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "icmp_flood_rate", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 1 || v > 10000000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "icmp_flood_rate must be 1..10000000"); }
        next.icmp_flood_rate = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "dns_amp_rate", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 1 || v > 10000000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "dns_amp_rate must be 1..10000000"); }
        next.dns_amp_rate = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "max_frags", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 1 || v > 100000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "max_frags must be 1..100000"); }
        next.max_frags = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "auto_block_enabled", &j_val)) {
        if (json_object_is_type(j_val, json_type_boolean)) {
            next.auto_block_enabled = json_object_get_boolean(j_val) ? 1U : 0U;
        } else {
            next.auto_block_enabled = json_object_get_int(j_val) ? 1U : 0U;
        }
    }
    if (json_object_object_get_ex(root, "auto_block_duration_sec", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 0 || v > 604800) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "auto_block_duration_sec must be 0..604800"); }
        next.auto_block_duration_sec = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "global_syn_rate", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 0 || v > 50000000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "global_syn_rate must be 0..50000000"); }
        next.global_syn_rate = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "global_udp_rate", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 0 || v > 50000000) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "global_udp_rate must be 0..50000000"); }
        next.global_udp_rate = (uint32_t)v;
    }
    if (json_object_object_get_ex(root, "max_dns_response_size", &j_val)) {
        int64_t v = json_object_get_int64(j_val);
        if (v < 64 || v > 65535) { json_object_put(root); return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "max_dns_response_size must be 64..65535"); }
        next.max_dns_response_size = (uint32_t)v;
    }

    *ctx->config = next;

    // Persist to SQLite config table so thresholds survive restarts
    if (ctx->db && ctx->db->is_open) {
        persist_u32_setting(ctx->db, "syn_flood_rate", next.syn_flood_rate);
        persist_u32_setting(ctx->db, "udp_flood_rate", next.udp_flood_rate);
        persist_u32_setting(ctx->db, "icmp_flood_rate", next.icmp_flood_rate);
        persist_u32_setting(ctx->db, "dns_amp_rate", next.dns_amp_rate);
        persist_u32_setting(ctx->db, "max_frags", next.max_frags);
        persist_u32_setting(ctx->db, "auto_block_enabled", next.auto_block_enabled);
        persist_u32_setting(ctx->db, "auto_block_duration_sec", next.auto_block_duration_sec);
        persist_u32_setting(ctx->db, "global_syn_rate", next.global_syn_rate);
        persist_u32_setting(ctx->db, "global_udp_rate", next.global_udp_rate);
        persist_u32_setting(ctx->db, "max_dns_response_size", next.max_dns_response_size);
    }

    // Update BPF config_map if attached
    if (ctx->fds && ctx->fds->config_map_fd >= 0) {
        struct attacks_config_t cfg;
        runtime_config_to_bpf_cfg(ctx->config, &cfg);
        uint32_t key = 0;
        if (bpf_map_update_elem(ctx->fds->config_map_fd, &key, &cfg, BPF_ANY) != 0) {
            json_object_put(root);
            return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to update BPF config map");
        }
    }

    json_object_put(root);
    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"settings updated\"}");
}
