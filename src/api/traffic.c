#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/common.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME CLOCK_MONOTONIC
#endif

// Handler: GET /api/v1/traffic/stats
enum MHD_Result api_traffic_stats(struct MHD_Connection *connection,
                                  struct api_context *ctx) {
    struct map_fds *fds = ctx ? ctx->fds : NULL;
    json_object *json_traffic = json_object_new_array();

    struct timespec ts_boot = {0};
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    uint64_t now_ns = (uint64_t)ts_boot.tv_sec * 1000000000ULL + (uint64_t)ts_boot.tv_nsec;
    time_t boot_time = time(NULL) - ts_boot.tv_sec;

    struct traffic_info_t info;
    struct flow_key_t key = {0}, next_key = {0};
    int count = 0;

    if (fds && fds->traffic_fd >= 0) {
        void *cur_key = NULL;
        while (bpf_map_get_next_key(fds->traffic_fd, cur_key, &next_key) == 0) {
            if (bpf_map_lookup_elem(fds->traffic_fd, &next_key, &info) == 0) {
                char src_ip[INET6_ADDRSTRLEN] = {0};
                char dst_ip[INET6_ADDRSTRLEN] = {0};
                cyrenus_ip_to_str(&info.src_ip, src_ip, sizeof(src_ip));
                cyrenus_ip_to_str(&info.dst_ip, dst_ip, sizeof(dst_ip));

                bool is_blocked = false;
                if (fds->auto_block_fd >= 0) {
                    struct auto_block_val ab;
                    if (bpf_map_lookup_elem(fds->auto_block_fd, &info.src_ip, &ab) == 0 &&
                        now_ns < ab.blocked_until_ns) {
                        is_blocked = true;
                    }
                }
                if (!is_blocked && fds->ip_blacklist_fd >= 0) {
                    struct ip_list_key lk = { .prefixlen = 128, .ip = info.src_ip };
                    uint8_t bval = 0;
                    if (bpf_map_lookup_elem(fds->ip_blacklist_fd, &lk, &bval) == 0 && bval == 1) {
                        is_blocked = true;
                    }
                }

                uint64_t dur_sec = 1;
                if (info.flow_end_time > info.flow_start_time) {
                    dur_sec = (info.flow_end_time - info.flow_start_time) / 1000000000ULL;
                    if (dur_sec == 0) dur_sec = 1;
                }
                time_t last_seen = boot_time + (time_t)(info.timestamp / 1000000000ULL);
                int64_t last_seen_age = (int64_t)(time(NULL) - last_seen);
                if (last_seen_age < 0) last_seen_age = 0;

                json_object *json_info = json_object_new_object();
                json_object_object_add(json_info, "src_ip", json_object_new_string(src_ip));
                json_object_object_add(json_info, "dst_ip", json_object_new_string(dst_ip));
                json_object_object_add(json_info, "ip_version",
                                       json_object_new_int(info.ip_version == 6 ? 6 : 4));
                json_object_object_add(json_info, "src_port", json_object_new_int(info.src_port));
                json_object_object_add(json_info, "dst_port", json_object_new_int(info.dst_port));
                json_object_object_add(json_info, "proto", json_object_new_int(info.proto));
                json_object_object_add(json_info, "proto_name", json_object_new_string(get_proto_name(info.proto)));
                json_object_object_add(json_info, "bytes", json_object_new_int64((int64_t)info.bytes));
                json_object_object_add(json_info, "packets", json_object_new_int64((int64_t)info.packets));
                json_object_object_add(json_info, "direction", json_object_new_string(info.direction == DIRECTION_INCOMING ? "IN" : "OUT"));
                json_object_object_add(json_info, "duration_sec", json_object_new_int64((int64_t)dur_sec));
                json_object_object_add(json_info, "last_seen_sec", json_object_new_int64(last_seen_age));
                json_object_object_add(json_info, "blocked", json_object_new_boolean(is_blocked));

                json_object_array_add(json_traffic, json_info);

                if (++count >= 500) break;
            }
            key = next_key;
            cur_key = &key;
        }
    }

    const char *json_str = json_object_to_json_string(json_traffic);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(json_traffic);
    return ret;
}
