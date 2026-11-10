#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
/*
 * Linux UAPI <linux/icmp.h> includes <linux/if.h>, which pulls in glibc
 * <sys/socket.h> -> <gnu/stubs-32.h> under `clang -target bpf` without
 * multilib headers. Provide IFNAMSIZ (used only by icmp_ext_echo_iio) and
 * skip <linux/if.h> when including <linux/icmp.h> for BPF.
 */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#ifndef _LINUX_IF_H
#define _LINUX_IF_H
#include <linux/icmp.h>
#undef _LINUX_IF_H
#else
#include <linux/icmp.h>
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/common.h"

#define FRAG_TIMEOUT 30000000000ULL
#define IP_CE 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define DNS_PORT 53
#define NTP_PORT 123
#define REPORT_INTERVAL_NS 1000000000ULL

struct token_bucket_t {
    __u64 last_update;
    __u32 tokens;
    __u32 pad;
};

struct syn_flood_info {
    __u64 last_update;
    __u64 syn_bytes;
    __u32 syn_count;
    __u32 synack_count;
};

struct dns_info {
    __u64 last_update;
    __u32 packet_count;
    __u32 total_size;
};

struct frag_info {
    __u64 last_update;
    __u32 frag_count;
    __u32 pad;
};

struct udp_flood_info {
    __u64 last_update;
    __u32 packet_count;
    __u32 byte_count;
};

// --- BPF Maps ---

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ATTACKS);
    __type(key, __u32);
    __type(value, struct attack_info);
} attack_info_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} attack_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct active_attack_key);
    __type(value, struct active_attack_val);
} active_attacks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct auto_block_val);
} auto_block_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10240);
    __type(key, struct ip_list_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10240);
    __type(key, struct ip_list_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats_t);
} global_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_rate_state);
} global_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct udp_flood_info);
} udp_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct frag_info);
} frag_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct dns_info);
} dns_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct syn_flood_info);
} syn_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct rule_key_t);
    __type(value, struct rule_t);
} rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRAFFIC_ENTRIES);
    __type(key, struct flow_key_t);
    __type(value, struct traffic_info_t);
} active_traffic SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} host_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct token_bucket_t);
} token_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 600000);
    __type(key, struct geoip_key);
    __type(value, __u16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geoip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} blocked_countries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct attacks_config_t);
} config_map SEC(".maps");

// --- Helpers ---

static __always_inline void get_config(struct attacks_config_t *cfg) {
    __u32 key = 0;
    struct attacks_config_t *map_cfg = bpf_map_lookup_elem(&config_map, &key);
    if (map_cfg &&
        (map_cfg->syn_flood_rate > 0 || map_cfg->udp_flood_rate > 0 ||
         map_cfg->icmp_flood_rate > 0 || map_cfg->dns_amp_rate > 0 ||
         map_cfg->max_frags > 0)) {
        *cfg = *map_cfg;
        if (cfg->syn_flood_rate == 0) cfg->syn_flood_rate = DEFAULT_SYN_FLOOD_RATE;
        if (cfg->udp_flood_rate == 0) cfg->udp_flood_rate = DEFAULT_UDP_FLOOD_RATE;
        if (cfg->icmp_flood_rate == 0) cfg->icmp_flood_rate = DEFAULT_ICMP_FLOOD_RATE;
        if (cfg->dns_amp_rate == 0) cfg->dns_amp_rate = DEFAULT_DNS_AMP_RATE;
        if (cfg->max_frags == 0) cfg->max_frags = DEFAULT_MAX_FRAGS;
        if (cfg->max_dns_response_size == 0) cfg->max_dns_response_size = DEFAULT_MAX_DNS_RESP_SIZE;
    } else {
        cfg->syn_flood_rate = DEFAULT_SYN_FLOOD_RATE;
        cfg->udp_flood_rate = DEFAULT_UDP_FLOOD_RATE;
        cfg->icmp_flood_rate = DEFAULT_ICMP_FLOOD_RATE;
        cfg->dns_amp_rate = DEFAULT_DNS_AMP_RATE;
        cfg->max_frags = DEFAULT_MAX_FRAGS;
        cfg->auto_block_enabled = DEFAULT_AUTO_BLOCK_ENABLED;
        cfg->auto_block_duration_sec = DEFAULT_AUTO_BLOCK_SEC;
        cfg->global_syn_rate = DEFAULT_GLOBAL_SYN_RATE;
        cfg->global_udp_rate = DEFAULT_GLOBAL_UDP_RATE;
        cfg->max_dns_response_size = DEFAULT_MAX_DNS_RESP_SIZE;
    }
}

static __always_inline int xdp_drop_stats(struct global_stats_t *stats, __u64 pkt_len, __u8 reason) {
    if (stats) {
        stats->dropped_packets++;
        stats->dropped_bytes += pkt_len;
        switch (reason) {
            case DROP_REASON_UDP:       stats->udp_drops++; break;
            case DROP_REASON_SYN:       stats->syn_drops++; break;
            case DROP_REASON_ICMP:      stats->icmp_drops++; break;
            case DROP_REASON_DNS:       stats->dns_drops++; break;
            case DROP_REASON_FRAG:      stats->frag_drops++; break;
            case DROP_REASON_RULE:      stats->rule_drops++; break;
            case DROP_REASON_GEO:       stats->geo_drops++; break;
            case DROP_REASON_AUTOBLOCK: stats->autoblock_drops++; break;
            default: break;
        }
    }
    return XDP_DROP;
}

static __always_inline void set_attack_type_name(char *dst, int attack_id) {
    switch (attack_id) {
        case ATK_ID_UDP_FLOOD:
            __builtin_memcpy(dst, "UDP Flood", 10);
            break;
        case ATK_ID_SYN_FLOOD:
            __builtin_memcpy(dst, "SYN Flood", 10);
            break;
        case ATK_ID_DNS_AMP:
            __builtin_memcpy(dst, "DNS Amplification", 18);
            break;
        case ATK_ID_ICMP_FLOOD:
            __builtin_memcpy(dst, "ICMP Flood", 11);
            break;
        case ATK_ID_FRAG_ATTACK:
            __builtin_memcpy(dst, "Fragment Attack", 16);
            break;
        case ATK_ID_GEOIP_BLOCK:
            __builtin_memcpy(dst, "GeoIP Block", 12);
            break;
        case ATK_ID_GLOBAL_SYN_FLOOD:
            __builtin_memcpy(dst, "Distributed SYN Flood", 22);
            break;
        case ATK_ID_GLOBAL_UDP_FLOOD:
            __builtin_memcpy(dst, "Distributed UDP Flood", 22);
            break;
        default:
            __builtin_memcpy(dst, "Unknown Attack", 15);
            break;
    }
}

static __always_inline void emit_ring_attack(
    __u32 src_ip, __u8 protocol, __u32 packets, __u64 bytes,
    __u32 peak_pps, int attack_id, __u8 blocked, __u64 now
) {
    __u32 index = 0;
    __u32 count = 0;

    __u32 *count_ptr = bpf_map_lookup_elem(&attack_count, &index);
    if (count_ptr) {
        count = __sync_fetch_and_add(count_ptr, 1);
        count = count % MAX_ATTACKS;
    }

    struct attack_info new_attack = {0};
    new_attack.timestamp = now;
    new_attack.src_ip = src_ip;
    new_attack.protocol = protocol;
    new_attack.packets = packets;
    new_attack.bytes = bytes;
    new_attack.peak_pps = peak_pps;
    new_attack.attack_id = (__u8)attack_id;
    new_attack.blocked = blocked;
    set_attack_type_name(new_attack.attack_type, attack_id);

    (void)bpf_map_update_elem(&attack_info_array, &count, &new_attack, BPF_ANY);
}

static __always_inline void record_attack(
    __u32 src_ip, __u8 protocol, int attack_id,
    __u32 window_packets, __u64 window_bytes, __u64 pkt_len,
    __u32 pps, const struct attacks_config_t *cfg, int allow_autoblock, __u64 now
) {
    __u8 will_block = 0;

    if (allow_autoblock && cfg && cfg->auto_block_enabled &&
        cfg->auto_block_duration_sec > 0 && src_ip != 0) {
        will_block = 1;
        __u64 until = now + (__u64)cfg->auto_block_duration_sec * 1000000000ULL;
        struct auto_block_val *ab = bpf_map_lookup_elem(&auto_block_map, &src_ip);
        if (ab) {
            ab->blocked_until_ns = until;
            ab->last_seen_ns = now;
            __sync_fetch_and_add(&ab->blocked_packets, 1);
            __sync_fetch_and_add(&ab->blocked_bytes, pkt_len);
            if (pps > ab->peak_pps) ab->peak_pps = pps;
        } else {
            struct auto_block_val new_ab = {0};
            new_ab.blocked_until_ns = until;
            new_ab.first_seen_ns = now;
            new_ab.last_seen_ns = now;
            new_ab.blocked_packets = 1;
            new_ab.blocked_bytes = pkt_len;
            new_ab.peak_pps = pps;
            new_ab.attack_id = (__u8)attack_id;
            new_ab.protocol = protocol;
            bpf_map_update_elem(&auto_block_map, &src_ip, &new_ab, BPF_ANY);
        }
    }

    struct active_attack_key akey = {0};
    akey.src_ip = src_ip;
    akey.attack_id = (__u8)attack_id;

    struct active_attack_val *aval = bpf_map_lookup_elem(&active_attacks_map, &akey);
    if (!aval) {
        struct active_attack_val new_val = {0};
        new_val.first_seen_ns = now;
        new_val.last_seen_ns = now;
        new_val.last_report_ns = now;
        new_val.packets = window_packets > 0 ? window_packets : 1;
        new_val.bytes = window_bytes > 0 ? window_bytes : pkt_len;
        new_val.dropped_packets = 1;
        new_val.dropped_bytes = pkt_len;
        new_val.peak_pps = pps;
        new_val.protocol = protocol;
        new_val.blocked = will_block;
        bpf_map_update_elem(&active_attacks_map, &akey, &new_val, BPF_ANY);

        emit_ring_attack(src_ip, protocol, new_val.packets, new_val.bytes,
                         pps, attack_id, will_block, now);
    } else {
        // Reset attack session stats if previous burst resolved (>30s idle)
        if (now > aval->last_seen_ns && (now - aval->last_seen_ns) > 30000000000ULL) {
            aval->first_seen_ns = now;
            aval->packets = window_packets > 0 ? window_packets : 1;
            aval->bytes = window_bytes > 0 ? window_bytes : pkt_len;
            aval->dropped_packets = 1;
            aval->dropped_bytes = pkt_len;
            aval->peak_pps = pps;
        } else {
            __sync_fetch_and_add(&aval->packets, 1);
            __sync_fetch_and_add(&aval->bytes, pkt_len);
            __sync_fetch_and_add(&aval->dropped_packets, 1);
            __sync_fetch_and_add(&aval->dropped_bytes, pkt_len);
            if (pps > aval->peak_pps) aval->peak_pps = pps;
        }
        aval->last_seen_ns = now;
        if (will_block) aval->blocked = 1;

        if (now >= aval->last_report_ns + REPORT_INTERVAL_NS) {
            aval->last_report_ns = now;
            emit_ring_attack(src_ip, protocol, aval->packets, aval->bytes,
                             aval->peak_pps, attack_id, aval->blocked, now);
        }
    }
}

static __always_inline void update_packet_length_stats(struct traffic_info_t *info, __u32 packet_length, __u8 direction) {
    if (direction == 0) {
        if (packet_length > info->fwd_packet_length_max)
            info->fwd_packet_length_max = packet_length;
        if (packet_length < info->fwd_packet_length_min || info->fwd_packet_length_min == 0)
            info->fwd_packet_length_min = packet_length;
        info->fwd_packet_length_sum += packet_length;
    } else {
        if (packet_length > info->bwd_packet_length_max)
            info->bwd_packet_length_max = packet_length;
        if (packet_length < info->bwd_packet_length_min || info->bwd_packet_length_min == 0)
            info->bwd_packet_length_min = packet_length;
        info->bwd_packet_length_sum += packet_length;
    }

    if (packet_length > info->max_packet_length)
        info->max_packet_length = packet_length;
    if (packet_length < info->min_packet_length || info->min_packet_length == 0)
        info->min_packet_length = packet_length;
}

static __always_inline void update_iat_stats(struct traffic_info_t *info, __u64 current_time, __u8 direction) {
    __u64 iat = current_time - info->timestamp;
    info->iat_sum += (__u32)iat;

    if (direction == 0)
        info->fwd_iat_sum += (__u32)iat;
    else
        info->bwd_iat_sum += (__u32)iat;
}

static __always_inline int is_established_flow(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto, __u64 now
) {
    struct flow_key_t key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = proto
    };

    struct traffic_info_t *flow = bpf_map_lookup_elem(&active_traffic, &key);
    if (!flow) return 0;

    __u64 flow_age = now - flow->flow_start_time;
    if (flow_age > 5000000000ULL && flow->packets > 10) {
        return 1;
    }
    return 0;
}

static __always_inline int check_ip_list(void *map, __u32 ip) {
    struct ip_list_key key = {
        .prefixlen = 32,
        .ip = ip
    };
    __u8 *val = bpf_map_lookup_elem(map, &key);
    return (val && *val == 1) ? 1 : 0;
}

// Returns ACTION_DROP (1), ACTION_PASS (2), or ACTION_NONE (0)
static __always_inline int apply_rule_for_ip(__u32 ip, __u16 port, __u8 proto) {
    struct rule_key_t key = {0};
    struct rule_t *rule;

    // 1. Exact IP + Port + Proto
    if (port != 0 && proto != 0) {
        key.ip = ip;
        key.port = bpf_htons(port);
        key.proto = proto;
        rule = bpf_map_lookup_elem(&rules, &key);
        if (rule) return rule->action;
    }

    // 2. Wildcard Port (0) + Exact Proto
    if (proto != 0) {
        key.ip = ip;
        key.port = 0;
        key.proto = proto;
        rule = bpf_map_lookup_elem(&rules, &key);
        if (rule) return rule->action;
    }

    // 3. Exact Port + Wildcard Proto (0)
    if (port != 0) {
        key.ip = ip;
        key.port = bpf_htons(port);
        key.proto = 0;
        rule = bpf_map_lookup_elem(&rules, &key);
        if (rule) return rule->action;
    }

    // 4. Wildcard Port (0) + Wildcard Proto (0) (All traffic for IP)
    key.ip = ip;
    key.port = 0;
    key.proto = 0;
    rule = bpf_map_lookup_elem(&rules, &key);
    if (rule) return rule->action;

    return ACTION_NONE;
}

static __always_inline int check_dns_amplification(
    struct iphdr *iph, struct udphdr *udph,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    __u32 src_ip = iph->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);

    if (src_port != DNS_PORT && dst_port != DNS_PORT) {
        return XDP_PASS;
    }

    int is_response = (src_port == DNS_PORT) ? 1 : 0;
    __u32 max_resp_size = cfg->max_dns_response_size > 0 ? cfg->max_dns_response_size : DEFAULT_MAX_DNS_RESP_SIZE;

    // Always inspect oversized UDP DNS amplification responses (even packet #1)
    if (is_response && pkt_len > max_resp_size) {
        record_attack(src_ip, IPPROTO_UDP, ATK_ID_DNS_AMP, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return XDP_DROP;
    }

    struct dns_info *info, new_info = {0};
    info = bpf_map_lookup_elem(&dns_track_map, &src_ip);

    if (!info) {
        new_info.last_update = now;
        new_info.packet_count = 1;
        new_info.total_size = (__u32)pkt_len;
        bpf_map_update_elem(&dns_track_map, &src_ip, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = (now > info->last_update) ? (now - info->last_update) : 0;

    if (elapsed < 1000000000ULL) {
        __sync_fetch_and_add(&info->packet_count, 1);
        __sync_fetch_and_add(&info->total_size, (__u32)pkt_len);

        int is_established = is_established_flow(src_ip, iph->daddr, src_port, dst_port, IPPROTO_UDP, now);
        __u32 threshold = cfg->dns_amp_rate;
        if (is_established) {
            threshold = cfg->dns_amp_rate * 5;
        }

        if (info->packet_count > threshold) {
            __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
            __u32 pps = (__u32)(((__u64)info->packet_count * 1000000000ULL) / denom);
            record_attack(src_ip, IPPROTO_UDP, ATK_ID_DNS_AMP,
                          info->packet_count, info->total_size, pkt_len, pps, cfg, 1, now);
            return XDP_DROP;
        }
    } else {
        info->last_update = now;
        info->packet_count = 1;
        info->total_size = (__u32)pkt_len;
    }

    return XDP_PASS;
}

static __always_inline int check_udp_flood(
    struct iphdr *iph, struct udphdr *udph,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now, int is_established
) {
    __u32 src_ip = iph->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    struct udp_flood_info *info, new_info = {0};

    // NTP amplification (Monlist / oversized NTP response)
    if ((dst_port == NTP_PORT || src_port == NTP_PORT) && pkt_len > 1024) {
        record_attack(src_ip, IPPROTO_UDP, ATK_ID_UDP_FLOOD, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return XDP_DROP;
    }

    info = bpf_map_lookup_elem(&udp_flood_map, &src_ip);
    if (!info) {
        new_info.last_update = now;
        new_info.packet_count = 1;
        new_info.byte_count = (__u32)pkt_len;
        bpf_map_update_elem(&udp_flood_map, &src_ip, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    __u64 time_diff = (now > info->last_update) ? (now - info->last_update) : 0;

    if (time_diff >= 1000000000ULL) {
        info->packet_count = 1;
        info->byte_count = (__u32)pkt_len;
        info->last_update = now;
        return XDP_PASS;
    }

    __sync_fetch_and_add(&info->packet_count, 1);
    __sync_fetch_and_add(&info->byte_count, (__u32)pkt_len);

    __u64 threshold = cfg->udp_flood_rate;
    if (is_established) {
        threshold = threshold * 10;
    }

    __u32 min_burst = (__u32)(threshold / 10);
    if (min_burst < 10) min_burst = 10;
    if (min_burst > 200) min_burst = 200;

    __u64 denom = time_diff > 10000000ULL ? time_diff : 10000000ULL;
    __u64 pps = ((__u64)info->packet_count * 1000000000ULL) / denom;

    // Trigger immediately if total packets in <1s already exceed full 1-second budget,
    // OR if sustained rate over >= 100ms exceeds threshold.
    if (info->packet_count > threshold ||
        (time_diff >= 100000000ULL && info->packet_count >= min_burst && pps > threshold)) {
        record_attack(src_ip, IPPROTO_UDP, ATK_ID_UDP_FLOOD,
                      info->packet_count, info->byte_count, pkt_len, (__u32)pps, cfg, 1, now);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int check_syn_flood(
    struct iphdr *iph, struct tcphdr *tcph,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    // Only count pure SYN packets (SYN=1, ACK=0) to avoid false positives on server SYN-ACK replies
    if (!(tcph->syn && !tcph->ack)) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;
    struct syn_flood_info *info, new_info = {0};

    info = bpf_map_lookup_elem(&syn_flood_map, &src_ip);
    if (!info) {
        new_info.last_update = now;
        new_info.syn_count = 1;
        new_info.syn_bytes = pkt_len;
        bpf_map_update_elem(&syn_flood_map, &src_ip, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = (now > info->last_update) ? (now - info->last_update) : 0;

    if (elapsed >= 1000000000ULL) {
        info->last_update = now;
        info->syn_count = 1;
        info->syn_bytes = pkt_len;
        return XDP_PASS;
    }

    __sync_fetch_and_add(&info->syn_count, 1);
    __sync_fetch_and_add(&info->syn_bytes, pkt_len);

    __u32 threshold = cfg->syn_flood_rate;
    __u32 min_burst = threshold / 10;
    if (min_burst < 10) min_burst = 10;
    if (min_burst > 100) min_burst = 100;

    __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
    __u64 pps = ((__u64)info->syn_count * 1000000000ULL) / denom;

    if (info->syn_count > threshold ||
        (elapsed >= 100000000ULL && info->syn_count >= min_burst && pps > threshold)) {
        record_attack(src_ip, IPPROTO_TCP, ATK_ID_SYN_FLOOD,
                      info->syn_count, info->syn_bytes, pkt_len, (__u32)pps, cfg, 1, now);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int check_icmp_flood(
    struct iphdr *iph, const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    struct token_bucket_t *bucket, new_bucket = {0};
    __u32 key = iph->saddr;
    __u32 rate = cfg->icmp_flood_rate > 0 ? cfg->icmp_flood_rate : DEFAULT_ICMP_FLOOD_RATE;

    bucket = bpf_map_lookup_elem(&token_buckets, &key);
    if (!bucket) {
        new_bucket.last_update = now;
        new_bucket.tokens = rate > 1 ? (rate - 1) : 0;
        bpf_map_update_elem(&token_buckets, &key, &new_bucket, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = (now > bucket->last_update) ? (now - bucket->last_update) : 0;
    __u32 new_tokens;

    if (elapsed >= 1000000000ULL) {
        new_tokens = rate;
    } else {
        __u64 refill = (elapsed * rate) / 1000000000ULL;
        new_tokens = bucket->tokens + (__u32)refill;
        if (new_tokens > rate) {
            new_tokens = rate;
        }
    }

    if (new_tokens >= 1) {
        bucket->tokens = new_tokens - 1;
        bucket->last_update = now;
        return XDP_PASS;
    }

    record_attack(iph->saddr, IPPROTO_ICMP, ATK_ID_ICMP_FLOOD,
                  rate + 1, pkt_len, pkt_len, rate, cfg, 1, now);
    return XDP_DROP;
}

static __always_inline int check_global_flood(
    __u8 proto, int is_pure_syn, int is_established,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    __u32 key = 0;
    struct global_rate_state *g = bpf_map_lookup_elem(&global_rate_map, &key);
    if (!g) return XDP_PASS;

    if (g->window_start_ns == 0 || (now > g->window_start_ns && (now - g->window_start_ns) >= 1000000000ULL)) {
        g->window_start_ns = now;
        g->syn_count = is_pure_syn ? 1 : 0;
        g->syn_bytes = is_pure_syn ? pkt_len : 0;
        g->udp_count = (proto == IPPROTO_UDP && !is_established) ? 1 : 0;
        g->udp_bytes = (proto == IPPROTO_UDP && !is_established) ? pkt_len : 0;
        return XDP_PASS;
    }

    if (is_pure_syn && cfg->global_syn_rate > 0) {
        __u32 cur = __sync_fetch_and_add(&g->syn_count, 1) + 1;
        __sync_fetch_and_add(&g->syn_bytes, pkt_len);
        if (cur > cfg->global_syn_rate) {
            __u64 elapsed = (now > g->window_start_ns) ? (now - g->window_start_ns) : 10000000ULL;
            __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
            __u32 pps = (__u32)(((__u64)cur * 1000000000ULL) / denom);
            record_attack(0, IPPROTO_TCP, ATK_ID_GLOBAL_SYN_FLOOD,
                          cur, g->syn_bytes, pkt_len, pps, cfg, 0, now);
            return XDP_DROP;
        }
    }

    if (proto == IPPROTO_UDP && !is_established && cfg->global_udp_rate > 0) {
        __u32 cur = __sync_fetch_and_add(&g->udp_count, 1) + 1;
        __sync_fetch_and_add(&g->udp_bytes, pkt_len);
        if (cur > cfg->global_udp_rate) {
            __u64 elapsed = (now > g->window_start_ns) ? (now - g->window_start_ns) : 10000000ULL;
            __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
            __u32 pps = (__u32)(((__u64)cur * 1000000000ULL) / denom);
            record_attack(0, IPPROTO_UDP, ATK_ID_GLOBAL_UDP_FLOOD,
                          cur, g->udp_bytes, pkt_len, pps, cfg, 0, now);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

static __always_inline int handle_fragment(
    struct iphdr *iph, const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    __u32 src_ip = iph->saddr;
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    __u16 frag_flags = frag_off & ~IP_OFFSET;
    __u16 frag_offset = frag_off & IP_OFFSET;

    if ((frag_flags & IP_MF) || frag_offset > 0) {
        struct frag_info *info, new_info = {0};

        if (frag_offset == 1) {
            record_attack(src_ip, iph->protocol, ATK_ID_FRAG_ATTACK, 1, pkt_len, pkt_len, 1, cfg, 1, now);
            return XDP_DROP;
        }

        __u16 tot_len = bpf_ntohs(iph->tot_len);
        __u16 ihl_bytes = iph->ihl * 4;
        __u16 ip_payload_len = (tot_len >= ihl_bytes) ? (tot_len - ihl_bytes) : 0;
        if ((frag_flags & IP_MF) && ip_payload_len < 16) {
            record_attack(src_ip, iph->protocol, ATK_ID_FRAG_ATTACK, 1, pkt_len, pkt_len, 1, cfg, 1, now);
            return XDP_DROP;
        }

        info = bpf_map_lookup_elem(&frag_track_map, &src_ip);
        if (!info) {
            new_info.last_update = now;
            new_info.frag_count = 1;
            bpf_map_update_elem(&frag_track_map, &src_ip, &new_info, BPF_ANY);
        } else {
            if (now > info->last_update && (now - info->last_update) > FRAG_TIMEOUT) {
                info->frag_count = 1;
            } else {
                __sync_fetch_and_add(&info->frag_count, 1);
            }
            info->last_update = now;

            if (info->frag_count > cfg->max_frags) {
                record_attack(src_ip, iph->protocol, ATK_ID_FRAG_ATTACK,
                              info->frag_count, pkt_len, pkt_len, info->frag_count, cfg, 1, now);
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

static __always_inline int check_geoip(
    __u32 src_ip, __u8 proto, const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    struct geoip_key key = {
        .prefixlen = 32,
        .ip = src_ip
    };

    __u16 *country_code_ptr = bpf_map_lookup_elem(&geoip_map, &key);
    if (!country_code_ptr) {
        return XDP_PASS;
    }

    __u16 country_code = *country_code_ptr;
    __u8 *action = bpf_map_lookup_elem(&blocked_countries, &country_code);
    if (action && *action == 1) {
        record_attack(src_ip, proto, ATK_ID_GEOIP_BLOCK, 1, pkt_len, pkt_len, 1, cfg, 0, now);
        return XDP_DROP;
    }

    return XDP_PASS;
}

// --- Main XDP Program ---

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u64 pkt_len = (__u64)(data_end - data);

    // Update global entry stats
    __u32 stats_key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key);
    if (stats) {
        stats->total_packets++;
        stats->total_bytes += pkt_len;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
        return xdp_drop_stats(stats, pkt_len, DROP_REASON_FRAG);

    __u32 ip_header_length = ip->ihl * 4;
    if (ip_header_length < sizeof(struct iphdr) || ip_header_length > 60)
        return xdp_drop_stats(stats, pkt_len, DROP_REASON_FRAG);

    if ((void *)ip + ip_header_length > data_end)
        return XDP_PASS;

    // Early sanity drops
    if (ip->saddr == 0 || ip->daddr == 0 || ip->ttl == 0)
        return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 proto = ip->protocol;
    __u64 now = bpf_ktime_get_ns();

    __u16 frag_off = bpf_ntohs(ip->frag_off);
    int is_nonfirst_frag = ((frag_off & IP_OFFSET) > 0) ? 1 : 0;

    __u16 src_port = 0, dst_port = 0;
    __u32 l4_header_length = 0;
    __u8 tcp_flags = 0;
    int is_pure_syn = 0;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;

    if (!is_nonfirst_frag) {
        if (proto == IPPROTO_TCP) {
            tcp = (void *)ip + ip_header_length;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
            l4_header_length = tcp->doff * 4;
            tcp_flags = *((__u8 *)tcp + 13);
            is_pure_syn = (tcp->syn && !tcp->ack) ? 1 : 0;
        } else if (proto == IPPROTO_UDP) {
            udp = (void *)ip + ip_header_length;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
            l4_header_length = sizeof(struct udphdr);
        } else if (proto == IPPROTO_ICMP) {
            struct icmphdr *icmp = (void *)ip + ip_header_length;
            if ((void *)(icmp + 1) > data_end)
                return XDP_PASS;
            src_port = icmp->type;
            dst_port = icmp->code;
            l4_header_length = sizeof(struct icmphdr);
        }
    }

    // 1. Whitelist check (LPM IP list or explicit PASS firewall rule)
    int is_whitelisted = check_ip_list(&ip_whitelist, src_ip);

    if (!is_whitelisted) {
        int src_rule = apply_rule_for_ip(src_ip, src_port, proto);
        if (src_rule == ACTION_DROP)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);
        if (src_rule == ACTION_PASS)
            is_whitelisted = 1;

        if (!is_whitelisted) {
            int dst_rule = apply_rule_for_ip(dst_ip, dst_port, proto);
            if (dst_rule == ACTION_DROP)
                return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);
            if (dst_rule == ACTION_PASS)
                is_whitelisted = 1;
        }
    }

    // 2. Explicit IP Blacklist check (blocks all protocols and fragments)
    if (!is_whitelisted && check_ip_list(&ip_blacklist, src_ip)) {
        return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);
    }

    // 3. Dynamic Mitigation & Flood Checks (skipped for explicitly whitelisted IPs)
    if (!is_whitelisted) {
        // 3a. Active Auto-Block Check (prevents 1s window-reset leakage)
        struct auto_block_val *ab = bpf_map_lookup_elem(&auto_block_map, &src_ip);
        if (ab) {
            if (now < ab->blocked_until_ns) {
                __sync_fetch_and_add(&ab->blocked_packets, 1);
                __sync_fetch_and_add(&ab->blocked_bytes, pkt_len);
                ab->last_seen_ns = now;

                struct active_attack_key akey = {
                    .src_ip = src_ip,
                    .attack_id = ab->attack_id
                };
                struct active_attack_val *aval = bpf_map_lookup_elem(&active_attacks_map, &akey);
                if (aval) {
                    __sync_fetch_and_add(&aval->packets, 1);
                    __sync_fetch_and_add(&aval->bytes, pkt_len);
                    __sync_fetch_and_add(&aval->dropped_packets, 1);
                    __sync_fetch_and_add(&aval->dropped_bytes, pkt_len);
                    aval->last_seen_ns = now;
                }
                return xdp_drop_stats(stats, pkt_len, DROP_REASON_AUTOBLOCK);
            } else {
                bpf_map_delete_elem(&auto_block_map, &src_ip);
            }
        }

        struct attacks_config_t cfg;
        get_config(&cfg);

        // 3b. GeoIP Country Block
        if (check_geoip(src_ip, proto, &cfg, pkt_len, now) != XDP_PASS)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_GEO);

        // 3c. IP Fragmentation Attacks
        if (handle_fragment(ip, &cfg, pkt_len, now) != XDP_PASS)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_FRAG);

        // 3d. Protocol-specific + Global Aggregate Flood Detection
        if (!is_nonfirst_frag) {
            if (proto == IPPROTO_TCP && tcp) {
                if (check_syn_flood(ip, tcp, &cfg, pkt_len, now) != XDP_PASS)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_SYN);
                if (check_global_flood(proto, is_pure_syn, 0, &cfg, pkt_len, now) != XDP_PASS)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_SYN);
            } else if (proto == IPPROTO_UDP && udp) {
                int est = is_established_flow(src_ip, dst_ip, src_port, dst_port, IPPROTO_UDP, now);
                if (check_dns_amplification(ip, udp, &cfg, pkt_len, now) != XDP_PASS)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_DNS);
                if (check_udp_flood(ip, udp, &cfg, pkt_len, now, est) != XDP_PASS)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_UDP);
                if (check_global_flood(proto, 0, est, &cfg, pkt_len, now) != XDP_PASS)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_UDP);
            } else if (proto == IPPROTO_ICMP) {
                if (ip->daddr != bpf_htonl(0xFFFFFFFF)) {
                    if (check_icmp_flood(ip, &cfg, pkt_len, now) != XDP_PASS)
                        return xdp_drop_stats(stats, pkt_len, DROP_REASON_ICMP);
                }
            }
        }
    }

    // 4. Record active traffic flow statistics for passed packets
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP) {
        __u32 tot_len = bpf_ntohs(ip->tot_len);
        __u32 payload_length = 0;
        if (tot_len >= ip_header_length + l4_header_length) {
            payload_length = tot_len - ip_header_length - l4_header_length;
        }

        __u32 index = 0;
        __u32 *host_ip_ptr = bpf_map_lookup_elem(&host_ip, &index);
        __u32 current_host_ip = host_ip_ptr ? *host_ip_ptr : 0;
        __u8 direction = (current_host_ip == dst_ip) ? DIRECTION_INCOMING : DIRECTION_OUTGOING;

        struct flow_key_t key = {0};
        key.src_ip = src_ip;
        key.dst_ip = dst_ip;
        key.src_port = src_port;
        key.dst_port = dst_port;
        key.proto = proto;

        struct traffic_info_t *info = bpf_map_lookup_elem(&active_traffic, &key);
        if (!info) {
            struct traffic_info_t new_info = {0};
            new_info.src_ip = src_ip;
            new_info.dst_ip = dst_ip;
            new_info.src_port = src_port;
            new_info.dst_port = dst_port;
            new_info.timestamp = now;
            new_info.direction = direction;
            new_info.host_ip = current_host_ip;
            new_info.proto = proto;
            new_info.bytes = payload_length;
            new_info.packets = 1;
            new_info.flow_start_time = now;
            new_info.flow_end_time = now;
            new_info.fwd_packets = 1;
            new_info.fwd_bytes = payload_length;
            new_info.fwd_header_length = ip_header_length + l4_header_length;
            update_packet_length_stats(&new_info, payload_length, 0);
            if (proto == IPPROTO_TCP) {
                new_info.fin_count = (tcp_flags & 0x01) ? 1 : 0;
                new_info.syn_count = (tcp_flags & 0x02) ? 1 : 0;
                new_info.rst_count = (tcp_flags & 0x04) ? 1 : 0;
                new_info.psh_count = (tcp_flags & 0x08) ? 1 : 0;
                new_info.ack_count = (tcp_flags & 0x10) ? 1 : 0;
                new_info.urg_count = (tcp_flags & 0x20) ? 1 : 0;
                new_info.cwe_count = (tcp_flags & 0x40) ? 1 : 0;
                new_info.ece_count = (tcp_flags & 0x80) ? 1 : 0;
            }
            bpf_map_update_elem(&active_traffic, &key, &new_info, BPF_ANY);
        } else {
            info->flow_end_time = now;
            info->packets++;
            info->bytes += payload_length;
            if (direction == 0) {
                info->fwd_packets++;
                info->fwd_bytes += payload_length;
                info->fwd_header_length += ip_header_length + l4_header_length;
            } else {
                info->bwd_packets++;
                info->bwd_bytes += payload_length;
                info->bwd_header_length += ip_header_length + l4_header_length;
            }
            update_packet_length_stats(info, payload_length, direction);
            update_iat_stats(info, now, direction);
            if (proto == IPPROTO_TCP) {
                info->fin_count += (tcp_flags & 0x01) ? 1 : 0;
                info->syn_count += (tcp_flags & 0x02) ? 1 : 0;
                info->rst_count += (tcp_flags & 0x04) ? 1 : 0;
                info->psh_count += (tcp_flags & 0x08) ? 1 : 0;
                info->ack_count += (tcp_flags & 0x10) ? 1 : 0;
                info->urg_count += (tcp_flags & 0x20) ? 1 : 0;
                info->cwe_count += (tcp_flags & 0x40) ? 1 : 0;
                info->ece_count += (tcp_flags & 0x80) ? 1 : 0;
            }
            info->timestamp = now;
        }
    }

    if (stats) {
        stats->passed_packets++;
        stats->passed_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
