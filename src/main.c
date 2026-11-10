#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <json-c/json.h>
#include "../include/runtime_config.h"
#include "../include/database.h"
#include "../include/bpf_loader.h"
#include "../include/http_server.h"
#include "../include/geoip_helpers.h"
#include "../include/websocket_server.h"
#include "../include/common.h"
#include "../include/saas_uplink.h"
#include "../include/api_handlers.h"
#include "../include/attack_info.h"
#include "../include/tetragon_events.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME CLOCK_MONOTONIC
#endif

// Global running flag to control main loop
static volatile sig_atomic_t running = 1;

// Global structs for cleanup
static struct runtime_config config;
static struct database db;
struct database *g_db = NULL; // Global database for security API

#define MAX_HOST_IPS 32

static int collect_interface_ips(const char *interface_name,
                                 struct cyrenus_ip *out, int max_ips, int *count_out) {
    if (!interface_name || !out || max_ips <= 0 || !count_out) return -1;
    *count_out = 0;

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        perror("getifaddrs");
        return -1;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL && *count_out < max_ips; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_name) continue;
        if (strcmp(ifa->ifa_name, interface_name) != 0) continue;

        struct cyrenus_ip cand = {0};
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            cyrenus_ip_from_v4(&cand, sin->sin_addr.s_addr);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            cyrenus_ip_from_v6(&cand, &sin6->sin6_addr);
        } else {
            continue;
        }

        // Deduplicate
        int dup = 0;
        for (int i = 0; i < *count_out; i++) {
            if (cyrenus_ip_equals(&out[i], &cand)) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            out[(*count_out)++] = cand;
        }
    }

    freeifaddrs(ifaddr);
    return (*count_out > 0) ? 0 : -1;
}

// Signal handler to catch termination signals
void signal_handler(int signum) {
    (void)signum;
    running = 0;
}

static void init_invalid_map_fds(struct map_fds *fds) {
    if (!fds) return;
    fds->rules_fd = -1;
    fds->traffic_fd = -1;
    fds->udp_flood_fd = -1;
    fds->dns_track_fd = -1;
    fds->syn_flood_fd = -1;
    fds->attack_info_array_fd = -1;
    fds->attack_count_fd = -1;
    fds->active_attacks_fd = -1;
    fds->auto_block_fd = -1;
    fds->ip_whitelist_fd = -1;
    fds->ip_blacklist_fd = -1;
    fds->geoip_map_fd = -1;
    fds->geoip6_map_fd = -1;
    fds->blocked_countries_fd = -1;
    fds->global_stats_fd = -1;
    fds->config_map_fd = -1;
    fds->host_ips_fd = -1;
}

static void load_u32_setting(struct database *d, const char *key, uint32_t *target,
                             uint32_t min_val, uint32_t max_val) {
    char buf[64];
    if (database_get_config(d, key, buf, sizeof(buf)) == 0 && buf[0] != '\0') {
        if (strcasecmp(buf, "true") == 0 && max_val >= 1) {
            *target = 1;
            return;
        }
        if (strcasecmp(buf, "false") == 0 && min_val == 0) {
            *target = 0;
            return;
        }
        char *end = NULL;
        unsigned long val = strtoul(buf, &end, 10);
        if (end && *end == '\0' && val >= min_val && val <= max_val) {
            *target = (uint32_t)val;
        }
    }
}

static void load_persisted_settings(struct database *d, struct runtime_config *rc) {
    if (!d || !d->is_open || !rc) return;
    load_u32_setting(d, "syn_flood_rate", &rc->syn_flood_rate, 1, 10000000);
    load_u32_setting(d, "udp_flood_rate", &rc->udp_flood_rate, 1, 10000000);
    load_u32_setting(d, "icmp_flood_rate", &rc->icmp_flood_rate, 1, 10000000);
    load_u32_setting(d, "dns_amp_rate", &rc->dns_amp_rate, 1, 10000000);
    load_u32_setting(d, "max_frags", &rc->max_frags, 1, 100000);
    load_u32_setting(d, "auto_block_enabled", &rc->auto_block_enabled, 0, 1);
    load_u32_setting(d, "auto_block_duration_sec", &rc->auto_block_duration_sec, 0, 604800);
    load_u32_setting(d, "global_syn_rate", &rc->global_syn_rate, 0, 50000000);
    load_u32_setting(d, "global_udp_rate", &rc->global_udp_rate, 0, 50000000);
    load_u32_setting(d, "max_dns_response_size", &rc->max_dns_response_size, 64, 65535);
    load_u32_setting(d, "rst_flood_rate", &rc->rst_flood_rate, 1, 10000000);
    load_u32_setting(d, "ack_flood_rate", &rc->ack_flood_rate, 1, 10000000);
    load_u32_setting(d, "synack_flood_rate", &rc->synack_flood_rate, 1, 10000000);
}

static void sync_ip_list_to_bpf(const struct ip_list_record *entries, int count, int map_fd) {
    if (!entries || count <= 0 || map_fd < 0) return;
    for (int i = 0; i < count; i++) {
        char canonical_ip[46] = {0};
        uint8_t cidr = 0;
        struct cyrenus_ip masked = {0};
        int af = AF_INET;
        if (cyrenus_parse_cidr(entries[i].ip_address, entries[i].cidr_range,
                               canonical_ip, &cidr, &masked, &af) != 0) {
            continue;
        }
        struct ip_list_key key = {
            .prefixlen = cyrenus_ip_to_lpm_prefix(af, cidr),
            .ip = masked
        };
        uint8_t val = 1;
        bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    }
}

static void sync_persisted_policies_to_bpf(struct database *d, const struct map_fds *fds) {
    if (!d || !d->is_open || !fds) return;

    // 1. Firewall Rules
    if (fds->rules_fd >= 0) {
        struct rule_record *rules = NULL;
        int rcount = 0;
        if (database_list_rules(d, &rules, &rcount) == 0 && rules) {
            int loaded = 0;
            for (int i = 0; i < rcount; i++) {
                if (!rules[i].enabled) continue;
                struct cyrenus_ip rule_ip = {0};
                if (strcmp(rules[i].ip_address, "0.0.0.0") != 0 &&
                    strcmp(rules[i].ip_address, "::") != 0) {
                    if (cyrenus_str_to_ip(rules[i].ip_address, &rule_ip, NULL) != 0) {
                        continue;
                    }
                }
                struct rule_key_t key = {
                    .ip = rule_ip,
                    .port = htons(rules[i].port_start),
                    .proto = rules[i].protocol
                };
                struct rule_t rule = {
                    .port_start = htons(rules[i].port_start),
                    .port_end = htons(rules[i].port_end),
                    .proto = rules[i].protocol,
                    .action = rules[i].action
                };
                if (bpf_map_update_elem(fds->rules_fd, &key, &rule, BPF_ANY) == 0) {
                    loaded++;
                }
            }
            printf("Synced %d persisted firewall rule(s) to eBPF map\n", loaded);
            database_free_rule_list(rules, rcount);
        }
    }

    // 2. IP Whitelist & Blacklist
    if (fds->ip_whitelist_fd >= 0) {
        struct ip_list_record *wl = NULL;
        int wl_count = 0;
        if (database_list_whitelist(d, &wl, &wl_count) == 0 && wl) {
            sync_ip_list_to_bpf(wl, wl_count, fds->ip_whitelist_fd);
            printf("Synced %d whitelist CIDR entry/entries to eBPF map\n", wl_count);
            database_free_ip_list(wl, wl_count);
        }
    }
    if (fds->ip_blacklist_fd >= 0) {
        struct ip_list_record *bl = NULL;
        int bl_count = 0;
        if (database_list_blacklist(d, &bl, &bl_count) == 0 && bl) {
            sync_ip_list_to_bpf(bl, bl_count, fds->ip_blacklist_fd);
            printf("Synced %d blacklist CIDR entry/entries to eBPF map\n", bl_count);
            database_free_ip_list(bl, bl_count);
        }
    }

    // 3. GeoIP Blocked Countries
    if (fds->blocked_countries_fd >= 0) {
        struct geo_rule_record *geo = NULL;
        int gcount = 0;
        if (database_list_geo_rules(d, &geo, &gcount) == 0 && geo) {
            int loaded = 0;
            for (int i = 0; i < gcount; i++) {
                if (strcasecmp(geo[i].action, "block") != 0 || strlen(geo[i].country_code) != 2) continue;
                uint16_t key = (uint16_t)(((unsigned char)toupper((unsigned char)geo[i].country_code[0]) << 8) |
                                          (unsigned char)toupper((unsigned char)geo[i].country_code[1]));
                uint8_t val = 1;
                if (bpf_map_update_elem(fds->blocked_countries_fd, &key, &val, BPF_ANY) == 0) {
                    loaded++;
                }
            }
            printf("Synced %d GeoIP block rule(s) to eBPF map\n", loaded);
            database_free_geo_rule_list(geo, gcount);
        }
    }
}

struct monitor_ctx {
    struct database *db;
    struct map_fds fds;
};

#define ALERT_TRACK_CAP 256
struct alert_track_entry {
    struct cyrenus_ip src_ip;
    uint8_t attack_id;
    uint64_t last_seen_ns;
};

static int should_emit_attack_alert(struct alert_track_entry *track, int *track_count,
                                    const struct cyrenus_ip *src_ip, uint8_t attack_id, uint64_t last_seen_ns) {
    for (int i = 0; i < *track_count; i++) {
        if (cyrenus_ip_equals(&track[i].src_ip, src_ip) && track[i].attack_id == attack_id) {
            int restart = (last_seen_ns > track[i].last_seen_ns &&
                           (last_seen_ns - track[i].last_seen_ns) > 30000000000ULL);
            track[i].last_seen_ns = last_seen_ns;
            return restart;
        }
    }

    int slot = (*track_count < ALERT_TRACK_CAP) ? (*track_count)++ : 0;
    if (slot == 0 && *track_count >= ALERT_TRACK_CAP) {
        // Evict oldest entry when table is full
        uint64_t oldest = track[0].last_seen_ns;
        for (int i = 1; i < ALERT_TRACK_CAP; i++) {
            if (track[i].last_seen_ns < oldest) {
                oldest = track[i].last_seen_ns;
                slot = i;
            }
        }
    }
    track[slot].src_ip = *src_ip;
    track[slot].attack_id = attack_id;
    track[slot].last_seen_ns = last_seen_ns;
    return 1;
}

static void broadcast_attack_alert(const struct attack_record *rec) {
    struct json_object *root = json_object_new_object();
    struct json_object *data = json_object_new_object();
    if (!root || !data) {
        if (root) json_object_put(root);
        if (data) json_object_put(data);
        return;
    }

    json_object_object_add(data, "src_ip", json_object_new_string(rec->src_ip));
    json_object_object_add(data, "attack_type", json_object_new_string(rec->attack_type));
    json_object_object_add(data, "protocol", json_object_new_string(rec->protocol));
    json_object_object_add(data, "severity", json_object_new_int(rec->severity));
    json_object_object_add(data, "packets", json_object_new_int64((int64_t)rec->packets));
    json_object_object_add(data, "dropped_packets", json_object_new_int64((int64_t)rec->dropped_packets));
    json_object_object_add(data, "peak_pps", json_object_new_int64((int64_t)rec->peak_pps));
    json_object_object_add(data, "blocked", json_object_new_boolean(rec->blocked));
    json_object_object_add(data, "status", json_object_new_string(rec->status));

    json_object_object_add(root, "type", json_object_new_string("attack_alert"));
    json_object_object_add(root, "data", data);

    const char *json_str = json_object_to_json_string(root);
    if (json_str) {
        ws_broadcast_message(json_str);
    }
    json_object_put(root);
}

// Monitor thread to poll eBPF stats/attacks, sync SQLite history, and broadcast WS updates
void *monitor_thread(void *arg) {
    struct monitor_ctx *ctx = (struct monitor_ctx *)arg;
    uint32_t key = 0;
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) num_cpus = 1;

    struct global_stats_t *values = calloc((size_t)num_cpus, sizeof(struct global_stats_t));
    if (!values) {
        fprintf(stderr, "Failed to allocate memory for monitor values\n");
        free(ctx);
        return NULL;
    }

    struct alert_track_entry alert_track[ALERT_TRACK_CAP] = {0};
    int alert_track_count = 0;

    uint64_t prev_total_packets = 0, prev_total_bytes = 0;
    uint64_t prev_passed_packets = 0, prev_passed_bytes = 0;
    uint64_t prev_dropped_packets = 0, prev_dropped_bytes = 0;
    int first_sample = 1;
    int loop_tick = 0;

    while (running) {
        uint64_t total_packets = 0, total_bytes = 0;
        uint64_t passed_packets = 0, passed_bytes = 0;
        uint64_t dropped_packets = 0, dropped_bytes = 0;

        if (ctx->fds.global_stats_fd >= 0) {
            if (bpf_map_lookup_elem(ctx->fds.global_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    total_packets += values[i].total_packets;
                    total_bytes += values[i].total_bytes;
                    passed_packets += values[i].passed_packets;
                    passed_bytes += values[i].passed_bytes;
                    dropped_packets += values[i].dropped_packets;
                    dropped_bytes += values[i].dropped_bytes;
                }
            }
        }

        uint32_t pps = (!first_sample && total_packets >= prev_total_packets)
                           ? (uint32_t)(total_packets - prev_total_packets) : 0;
        uint64_t bps = (!first_sample && total_bytes >= prev_total_bytes)
                           ? (total_bytes - prev_total_bytes) * 8 : 0;
        uint32_t passed_pps = (!first_sample && passed_packets >= prev_passed_packets)
                                  ? (uint32_t)(passed_packets - prev_passed_packets) : 0;
        uint64_t passed_bps = (!first_sample && passed_bytes >= prev_passed_bytes)
                                  ? (passed_bytes - prev_passed_bytes) * 8 : 0;
        uint32_t dropped_pps = (!first_sample && dropped_packets >= prev_dropped_packets)
                                   ? (uint32_t)(dropped_packets - prev_dropped_packets) : 0;
        uint64_t dropped_bps = (!first_sample && dropped_bytes >= prev_dropped_bytes)
                                   ? (dropped_bytes - prev_dropped_bytes) * 8 : 0;

        prev_total_packets = total_packets;
        prev_total_bytes = total_bytes;
        prev_passed_packets = passed_packets;
        prev_passed_bytes = passed_bytes;
        prev_dropped_packets = dropped_packets;
        prev_dropped_bytes = dropped_bytes;
        first_sample = 0;

        struct timespec ts_boot = {0};
        clock_gettime(CLOCK_BOOTTIME, &ts_boot);
        uint64_t now_ns = (uint64_t)ts_boot.tv_sec * 1000000000ULL + (uint64_t)ts_boot.tv_nsec;
        time_t now_unix = time(NULL);
        time_t boot_unix = now_unix - ts_boot.tv_sec;

        // Count active auto-blocks and purge long-expired entries (>60s past expiry)
        int active_blocks = 0;
        if (ctx->fds.auto_block_fd >= 0) {
            struct cyrenus_ip k = {0}, nk = {0};
            void *cur = NULL;
            struct auto_block_val val;
            struct cyrenus_ip expired_ips[64];
            int expired_n = 0;

            while (bpf_map_get_next_key(ctx->fds.auto_block_fd, cur, &nk) == 0) {
                if (bpf_map_lookup_elem(ctx->fds.auto_block_fd, &nk, &val) == 0) {
                    if (now_ns < val.blocked_until_ns) {
                        active_blocks++;
                    } else if (val.blocked_until_ns > 0 &&
                               now_ns > val.blocked_until_ns + 60000000000ULL &&
                               expired_n < 64) {
                        expired_ips[expired_n++] = nk;
                    }
                }
                k = nk;
                cur = &k;
            }
            for (int i = 0; i < expired_n; i++) {
                bpf_map_delete_elem(ctx->fds.auto_block_fd, &expired_ips[i]);
            }
        }

        // Sync active_attacks_map -> SQLite & emit attack_alert WebSocket messages
        int active_attacks = 0;
        if (ctx->fds.active_attacks_fd >= 0) {
            struct active_attack_entry *entries = NULL;
            int count = get_active_attacks(&entries, ctx->fds.active_attacks_fd);

            for (int i = 0; i < count; i++) {
                struct active_attack_key *ak = &entries[i].key;
                struct active_attack_val *av = &entries[i].val;
                if (av->packets == 0) continue;

                uint64_t age_ns = (now_ns >= av->last_seen_ns) ? (now_ns - av->last_seen_ns) : 0;
                int is_active = (age_ns <= 30000000000ULL);
                if (is_active) {
                    active_attacks++;
                }

                // Only sync active or recently transitioned attacks to SQLite
                if (age_ns <= 35000000000ULL) {
                    bool currently_blocked = (av->blocked != 0);
                    if (ctx->fds.auto_block_fd >= 0 && !cyrenus_ip_is_zero(&ak->src_ip)) {
                        struct auto_block_val ab;
                        if (bpf_map_lookup_elem(ctx->fds.auto_block_fd, &ak->src_ip, &ab) == 0 &&
                            now_ns < ab.blocked_until_ns) {
                            currently_blocked = true;
                        }
                    }

                    struct attack_record rec = {0};
                    time_t last_unix = boot_unix + (time_t)(av->last_seen_ns / 1000000000ULL);
                    if (last_unix > now_unix) last_unix = now_unix;
                    rec.timestamp = (int64_t)last_unix;

                    if (cyrenus_ip_is_zero(&ak->src_ip)) {
                        snprintf(rec.src_ip, sizeof(rec.src_ip), "0.0.0.0");
                    } else {
                        cyrenus_ip_to_str(&ak->src_ip, rec.src_ip, sizeof(rec.src_ip));
                    }

                    snprintf(rec.attack_type, sizeof(rec.attack_type), "%s", get_attack_name_by_id(ak->attack_id));
                    snprintf(rec.protocol, sizeof(rec.protocol), "%s", get_proto_name(av->protocol));
                    rec.severity = get_attack_severity(ak->attack_id, av->peak_pps, av->packets);
                    rec.packets = av->packets;
                    rec.bytes = av->bytes;
                    rec.dropped_packets = av->dropped_packets;
                    rec.dropped_bytes = av->dropped_bytes;
                    rec.peak_pps = av->peak_pps;
                    rec.duration = (av->last_seen_ns >= av->first_seen_ns)
                                       ? (int)((av->last_seen_ns - av->first_seen_ns) / 1000000000ULL)
                                       : 0;
                    if (rec.duration < 1) rec.duration = 1;
                    rec.blocked = currently_blocked;

                    if (is_active) {
                        snprintf(rec.status, sizeof(rec.status), "active");
                    } else if (av->dropped_packets > 0 || currently_blocked) {
                        snprintf(rec.status, sizeof(rec.status), "mitigated");
                    } else {
                        snprintf(rec.status, sizeof(rec.status), "resolved");
                    }

                    if (ctx->db && ctx->db->is_open) {
                        database_upsert_active_attack(ctx->db, &rec);
                    }

                    if (is_active &&
                        should_emit_attack_alert(alert_track, &alert_track_count,
                                                 &ak->src_ip, ak->attack_id, av->last_seen_ns)) {
                        broadcast_attack_alert(&rec);
                    }
                }
            }
            if (entries) free(entries);
        }

        // Transition attacks idle > 30s in DB from 'active' -> 'mitigated'
        if ((loop_tick % 5 == 0) && ctx->db && ctx->db->is_open) {
            database_finalize_stale_attacks(ctx->db, now_unix - 30);
        }
        loop_tick++;

        char msg[1024];
        snprintf(msg, sizeof(msg),
                 "{\"type\":\"traffic_update\",\"data\":{"
                 "\"timestamp\":%lld,"
                 "\"pps\":%u,\"bps\":%llu,"
                 "\"passed_pps\":%u,\"passed_bps\":%llu,"
                 "\"dropped_pps\":%u,\"dropped_bps\":%llu,"
                 "\"total_packets\":%llu,\"total_bytes\":%llu,"
                 "\"passed_packets\":%llu,\"dropped_packets\":%llu,\"dropped_bytes\":%llu,"
                 "\"active_attacks\":%d,\"active_blocks\":%d}}",
                 (long long)now_unix,
                 pps, (unsigned long long)bps,
                 passed_pps, (unsigned long long)passed_bps,
                 dropped_pps, (unsigned long long)dropped_bps,
                 (unsigned long long)total_packets, (unsigned long long)total_bytes,
                 (unsigned long long)passed_packets, (unsigned long long)dropped_packets,
                 (unsigned long long)dropped_bytes,
                 active_attacks, active_blocks);

        ws_broadcast_message(msg);

        // Sleep ~1 second in responsive 100ms chunks so shutdown joins quickly
        for (int s = 0; s < 10 && running; s++) {
            usleep(100000);
        }
    }

    free(values);
    free(ctx);
    return NULL;
}

int main(int argc, char **argv) {
    // 1. Initialize and load runtime configuration
    runtime_config_init(&config);

    // Load environment variables first
    runtime_config_load_env(&config);

    // Parse command line arguments (can override env)
    if (runtime_config_parse_args(argc, argv, &config) != 0) {
        return EXIT_FAILURE;
    }

    // Load config file (using path from args/defaults), then re-apply env & CLI overrides
    if (access(config.config_file_path, R_OK) == 0) {
        printf("Loading configuration from %s...\n", config.config_file_path);
        if (runtime_config_load_file(&config) != 0) {
            fprintf(stderr, "Failed to load config file\n");
            return EXIT_FAILURE;
        }
        runtime_config_load_env(&config);
        runtime_config_parse_args(argc, argv, &config);
    } else {
        printf("Warning: Config file %s not found, using defaults/args\n", config.config_file_path);
    }

    // Validate configuration
    if (runtime_config_validate(&config) != 0) {
        return EXIT_FAILURE;
    }

    // 2. Initialize and open database
    printf("Initializing database at %s...\n", config.database_path);
    if (database_init(&db, config.database_path, config.master_key_path) != 0) {
        fprintf(stderr, "Failed to initialize database\n");
        return EXIT_FAILURE;
    }

    if (database_open(&db) != 0) {
        fprintf(stderr, "Failed to open database\n");
        return EXIT_FAILURE;
    }

    // Create/migrate schema if needed
    if (database_create_schema(&db) != 0) {
        fprintf(stderr, "Failed to create database schema\n");
        database_close(&db);
        return EXIT_FAILURE;
    }

    // Expose DB globally for Tetragon/Security API regardless of inotify startup order
    g_db = &db;

    // Restore persisted detection/auto-block settings saved via API
    load_persisted_settings(&db, &config);

    if (config.verbose) {
        runtime_config_print(&config);
    }

    // Initialize GeoIP if configured
    if (!config.no_geoip && config.geoip_db_path[0] != '\0' && access(config.geoip_db_path, F_OK) == 0) {
        if (geoip_init(config.geoip_db_path) == 0) {
            printf("GeoIP initialized with %s\n", config.geoip_db_path);
        }
    }

    // 3. Network Setup
    struct cyrenus_ip host_ips[MAX_HOST_IPS] = {0};
    int host_ip_count = 0;
    if (collect_interface_ips(config.interface, host_ips, MAX_HOST_IPS, &host_ip_count) != 0) {
        if (config.dry_run) {
            fprintf(stderr, "Warning: Failed to get IP for interface %s, using 127.0.0.1 in dry-run mode\n", config.interface);
            cyrenus_ip_from_v4(&host_ips[0], htonl(INADDR_LOOPBACK));
            host_ip_count = 1;
        } else {
            fprintf(stderr, "Failed to get IP address for interface %s\n", config.interface);
            database_close(&db);
            return EXIT_FAILURE;
        }
    }
    char primary_ip_str[64] = {0};
    cyrenus_ip_to_str(&host_ips[0], primary_ip_str, sizeof(primary_ip_str));
    printf("Detected %d host IP(s) on %s (primary: %s)\n", host_ip_count, config.interface, primary_ip_str);

    // 4. Load eBPF Program
    struct map_fds fds;
    init_invalid_map_fds(&fds);

    struct attacks_config_t initial_cfg;
    runtime_config_to_bpf_cfg(&config, &initial_cfg);

    if (!config.dry_run) {
        const char *obj_path = (access("/usr/local/lib/cyrenus_xdp_prog.o", R_OK) == 0)
                                   ? "/usr/local/lib/cyrenus_xdp_prog.o"
                                   : "./build/xdp_prog.o";
        if (load_bpf_program(obj_path, config.interface, host_ips, host_ip_count,
                             &initial_cfg, &fds,
                             config.xdp_mode, sizeof(config.xdp_mode)) != 0) {
            fprintf(stderr, "Failed to load BPF program\n");
            database_close(&db);
            return EXIT_FAILURE;
        }

        // Populate GeoIP BPF maps (IPv4 and IPv6, if configured)
        if (!config.no_geoip && config.geoip_db_path[0] != '\0') {
            geoip_populate_bpf_maps(fds.geoip_map_fd, fds.geoip6_map_fd);
        }

        // Sync persisted firewall rules, IP lists, and GeoIP rules into BPF maps
        sync_persisted_policies_to_bpf(&db, &fds);
    } else {
        snprintf(config.xdp_mode, sizeof(config.xdp_mode), "Dry Run");
        printf("Dry run: BPF program loading skipped\n");
    }

    // 5. Start HTTP Server
    struct MHD_Daemon *daemon = start_http_server(&config, &db, &fds);
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server on port %d\n", config.http_port);
        if (!config.dry_run) unload_bpf_program(config.interface);
        database_close(&db);
        return EXIT_FAILURE;
    }

    // 6. Start WebSocket Server
    int ws_started = 0;
    pthread_t ws_thread_id;
    if (ws_server_init(&config, &db) == 0) {
        if (pthread_create(&ws_thread_id, NULL, ws_server_thread, NULL) == 0) {
            ws_started = 1;
        } else {
            fprintf(stderr, "Failed to create WebSocket thread\n");
        }
    } else {
        fprintf(stderr, "Failed to start WebSocket server\n");
    }

    // 7. Start Monitor Thread
    int monitor_started = 0;
    pthread_t monitor_tid;
    struct monitor_ctx *m_ctx = malloc(sizeof(struct monitor_ctx));
    if (m_ctx) {
        m_ctx->db = &db;
        m_ctx->fds = fds;
        if (pthread_create(&monitor_tid, NULL, monitor_thread, m_ctx) == 0) {
            monitor_started = 1;
        } else {
            fprintf(stderr, "Failed to create monitor thread\n");
            free(m_ctx);
        }
    }

    // 8. Start SaaS Uplink Thread
    struct saas_context *saas_ctx = malloc(sizeof(struct saas_context));
    if (saas_ctx) {
        struct map_fds *fds_ptr = malloc(sizeof(struct map_fds));
        if (fds_ptr) {
            *fds_ptr = fds;
            saas_uplink_init(saas_ctx, &config, &db, fds_ptr);
            pthread_t saas_tid;
            if (pthread_create(&saas_tid, NULL, saas_uplink_thread, saas_ctx) != 0) {
                fprintf(stderr, "Failed to create SaaS thread\n");
                free(fds_ptr);
                free(saas_ctx);
            } else {
                pthread_detach(saas_tid);
            }
        } else {
            free(saas_ctx);
        }
    }

    // 9. Initialize and Start Tetragon Event Monitor
    printf("Initializing Tetragon event monitor...\n");
    const char *env_tlog = getenv("CYRENUS_TETRAGON_LOG");
    const char *tetragon_log_path = (env_tlog && env_tlog[0]) ? env_tlog : "/var/log/tetragon/tetragon.log";
    if (tetragon_init(tetragon_log_path) == 0) {
        printf("Tetragon monitor initialized for: %s\n", tetragon_log_path);
        if (tetragon_start_monitor() == 0) {
            printf("Tetragon event monitor started successfully\n");
        } else {
            fprintf(stderr, "Warning: Failed to start Tetragon monitor thread\n");
        }
    } else {
        fprintf(stderr, "Warning: Failed to initialize Tetragon monitor\n");
        fprintf(stderr, "Security event monitoring will not be available.\n");
    }

    // Set up signal handlers to catch termination signals (SIGINT, SIGTERM)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Cyrenus is running on %s:%d (interface IP %s). Press Ctrl+C to stop.\n",
           config.bind_address[0] ? config.bind_address : "0.0.0.0",
           config.http_port, primary_ip_str);

    // Main loop
    while (running) {
        usleep(200000);
    }

    // Cleanup resources on termination
    if (saas_ctx) saas_uplink_cleanup(saas_ctx);
    printf("Stopping HTTP server...\n");
    stop_http_server(daemon);

    if (monitor_started) {
        pthread_join(monitor_tid, NULL);
    }

    tetragon_cleanup();

    printf("Stopping WebSocket server...\n");
    ws_server_cleanup();
    if (ws_started) {
        pthread_join(ws_thread_id, NULL);
    }

    if (!config.dry_run) {
        printf("Unloading BPF program...\n");
        unload_bpf_program(config.interface);
    }

    geoip_cleanup();

    printf("Closing database...\n");
    database_close(&db);

    printf("Cyrenus has stopped.\n");

    return EXIT_SUCCESS;
}
