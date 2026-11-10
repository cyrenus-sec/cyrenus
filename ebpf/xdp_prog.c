#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
/*
 * Linux UAPI <linux/icmp.h> includes <linux/if.h>, which pulls in glibc
 * <sys/socket.h> -> <gnu/stubs-32.h> under `clang -target bpf` without
 * multilib headers. Provide IFNAMSIZ and skip <linux/if.h> when including
 * <linux/icmp.h> for BPF.
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
#define REPORT_INTERVAL_NS 1000000000ULL

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define CY_IPPROTO_HOPOPTS  0
#define CY_IPPROTO_ROUTING  43
#define CY_IPPROTO_FRAGMENT 44
#define CY_IPPROTO_DSTOPTS  60

#define PORT_CHARGEN   19
#define PORT_DNS       53
#define PORT_NTP       123
#define PORT_SNMP      161
#define PORT_CLDAP     389
#define PORT_SSDP      1900
#define PORT_MEMCACHED 11211

struct cyrenus_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct cyrenus_ipv6_opt_hdr {
    __u8 nexthdr;
    __u8 hdrlen;
};

struct cyrenus_frag_hdr {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

struct cyrenus_icmp6_hdr {
    __u8 icmp6_type;
    __u8 icmp6_code;
    __sum16 icmp6_cksum;
    __u32 icmp6_data32;
};

struct token_bucket_t {
    __u64 last_update;
    __u32 tokens;
    __u32 pad;
};

struct syn_flood_info {
    __u64 last_update;
    __u64 window_bytes;
    __u32 syn_count;
    __u32 synack_count;
    __u32 rst_count;
    __u32 ack_fin_count;
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

struct xdp_scratch {
    struct traffic_info_t flow;
    struct attack_info atk;
    struct flow_key_t fkey;
    struct flow_key_t rev_fkey;
};

// --- BPF Maps ---

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_scratch);
} scratch_map SEC(".maps");

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
    __type(key, struct cyrenus_ip);
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
    __type(key, struct cyrenus_ip);
    __type(value, struct udp_flood_info);
} udp_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct cyrenus_ip);
    __type(value, struct frag_info);
} frag_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct cyrenus_ip);
    __type(value, struct dns_info);
} dns_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct cyrenus_ip);
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct cyrenus_ip);
    __type(value, __u8);
} host_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct cyrenus_ip);
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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 200000);
    __type(key, struct geoip6_key);
    __type(value, __u16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geoip6_map SEC(".maps");

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

// --- IP Helpers ---

static __always_inline void ip_from_v4(struct cyrenus_ip *out, __u32 v4_be) {
    out->addr[0] = 0;
    out->addr[1] = 0;
    out->addr[2] = bpf_htonl(0x0000ffff);
    out->addr[3] = v4_be;
}

static __always_inline int ip_is_zero(const struct cyrenus_ip *ip) {
    return (ip->addr[0] | ip->addr[1] | ip->addr[2] | ip->addr[3]) == 0;
}

static __always_inline int ip_is_v4_mapped(const struct cyrenus_ip *ip) {
    return (ip->addr[0] == 0 && ip->addr[1] == 0 && ip->addr[2] == bpf_htonl(0x0000ffff));
}

// --- Config & Telemetry Helpers ---

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
        if (cfg->rst_flood_rate == 0) cfg->rst_flood_rate = DEFAULT_RST_FLOOD_RATE;
        if (cfg->ack_flood_rate == 0) cfg->ack_flood_rate = DEFAULT_ACK_FLOOD_RATE;
        if (cfg->synack_flood_rate == 0) cfg->synack_flood_rate = DEFAULT_SYNACK_FLOOD_RATE;
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
        cfg->rst_flood_rate = DEFAULT_RST_FLOOD_RATE;
        cfg->ack_flood_rate = DEFAULT_ACK_FLOOD_RATE;
        cfg->synack_flood_rate = DEFAULT_SYNACK_FLOOD_RATE;
        cfg->pad = 0;
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
            case DROP_REASON_AMP:       stats->amp_drops++; break;
            case DROP_REASON_ACK:       stats->ack_drops++; break;
            case DROP_REASON_RST:       stats->rst_drops++; break;
            case DROP_REASON_MALFORMED: stats->malformed_drops++; break;
            default: break;
        }
    }
    return XDP_DROP;
}

static __always_inline void set_attack_type_name(char *dst, int attack_id) {
    switch (attack_id) {
        case ATK_ID_UDP_FLOOD:        __builtin_memcpy(dst, "UDP Flood", 10); break;
        case ATK_ID_SYN_FLOOD:        __builtin_memcpy(dst, "SYN Flood", 10); break;
        case ATK_ID_DNS_AMP:          __builtin_memcpy(dst, "DNS Amplification", 18); break;
        case ATK_ID_ICMP_FLOOD:       __builtin_memcpy(dst, "ICMP Flood", 11); break;
        case ATK_ID_FRAG_ATTACK:      __builtin_memcpy(dst, "Fragment Attack", 16); break;
        case ATK_ID_GEOIP_BLOCK:      __builtin_memcpy(dst, "GeoIP Block", 12); break;
        case ATK_ID_GLOBAL_SYN_FLOOD: __builtin_memcpy(dst, "Distributed SYN Flood", 22); break;
        case ATK_ID_GLOBAL_UDP_FLOOD: __builtin_memcpy(dst, "Distributed UDP Flood", 22); break;
        case ATK_ID_UDP_AMP:          __builtin_memcpy(dst, "UDP Amplification", 18); break;
        case ATK_ID_ACK_FLOOD:        __builtin_memcpy(dst, "TCP ACK Flood", 14); break;
        case ATK_ID_RST_FLOOD:        __builtin_memcpy(dst, "TCP RST Flood", 14); break;
        case ATK_ID_SYNACK_FLOOD:     __builtin_memcpy(dst, "SYN-ACK Reflection", 19); break;
        case ATK_ID_MALFORMED_PKT:    __builtin_memcpy(dst, "Malformed Packet", 17); break;
        default:                      __builtin_memcpy(dst, "Unknown Attack", 15); break;
    }
}

static __always_inline void emit_ring_attack(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, __u8 protocol, __u32 packets, __u64 bytes,
    __u32 peak_pps, int attack_id, __u8 blocked, __u64 now
) {
    if (!sc) return;

    __u32 index = 0;
    __u32 count = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&attack_count, &index);
    if (count_ptr) {
        count = __sync_fetch_and_add(count_ptr, 1);
        count = count % MAX_ATTACKS;
    }

    __builtin_memset(&sc->atk, 0, sizeof(sc->atk));
    sc->atk.timestamp = now;
    sc->atk.src_ip = *src_ip;
    sc->atk.protocol = protocol;
    sc->atk.packets = packets;
    sc->atk.bytes = bytes;
    sc->atk.peak_pps = peak_pps;
    sc->atk.attack_id = (__u8)attack_id;
    sc->atk.blocked = blocked;
    set_attack_type_name(sc->atk.attack_type, attack_id);

    (void)bpf_map_update_elem(&attack_info_array, &count, &sc->atk, BPF_ANY);
}

static __always_inline void record_attack(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, __u8 protocol, int attack_id,
    __u32 window_packets, __u64 window_bytes, __u64 pkt_len,
    __u32 pps, const struct attacks_config_t *cfg, int allow_autoblock, __u64 now
) {
    __u8 will_block = 0;

    if (allow_autoblock && cfg && cfg->auto_block_enabled &&
        cfg->auto_block_duration_sec > 0 && !ip_is_zero(src_ip)) {
        will_block = 1;
        __u64 until = now + (__u64)cfg->auto_block_duration_sec * 1000000000ULL;
        struct auto_block_val *ab = bpf_map_lookup_elem(&auto_block_map, src_ip);
        if (ab) {
            ab->blocked_until_ns = until;
            ab->last_seen_ns = now;
            __sync_fetch_and_add(&ab->blocked_packets, 1);
            __sync_fetch_and_add(&ab->blocked_bytes, pkt_len);
            if (pps > ab->peak_pps) ab->peak_pps = pps;
        } else {
            struct auto_block_val new_ab;
            __builtin_memset(&new_ab, 0, sizeof(new_ab));
            new_ab.blocked_until_ns = until;
            new_ab.first_seen_ns = now;
            new_ab.last_seen_ns = now;
            new_ab.blocked_packets = 1;
            new_ab.blocked_bytes = pkt_len;
            new_ab.peak_pps = pps;
            new_ab.attack_id = (__u8)attack_id;
            new_ab.protocol = protocol;
            bpf_map_update_elem(&auto_block_map, src_ip, &new_ab, BPF_ANY);
        }
    }

    struct active_attack_key akey;
    __builtin_memset(&akey, 0, sizeof(akey));
    akey.src_ip = *src_ip;
    akey.attack_id = (__u8)attack_id;

    struct active_attack_val *aval = bpf_map_lookup_elem(&active_attacks_map, &akey);
    if (!aval) {
        struct active_attack_val new_val;
        __builtin_memset(&new_val, 0, sizeof(new_val));
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

        emit_ring_attack(sc, src_ip, protocol, new_val.packets, new_val.bytes,
                         pps, attack_id, will_block, now);
    } else {
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
            emit_ring_attack(sc, src_ip, protocol, aval->packets, aval->bytes,
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
        info->max_packet_length = (__u16)packet_length;
    if (packet_length < info->min_packet_length || info->min_packet_length == 0)
        info->min_packet_length = (__u16)packet_length;
}

static __always_inline void update_iat_stats(struct traffic_info_t *info, __u64 current_time, __u8 direction) {
    __u64 iat = current_time - info->timestamp;
    info->iat_sum += (__u32)iat;

    if (direction == 0)
        info->fwd_iat_sum += (__u32)iat;
    else
        info->bwd_iat_sum += (__u32)iat;
}

static __always_inline int is_established_udp_flow(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, const struct cyrenus_ip *dst_ip,
    __u16 src_port, __u16 dst_port, __u64 now
) {
    if (!sc) return 0;
    __builtin_memset(&sc->fkey, 0, sizeof(sc->fkey));
    sc->fkey.src_ip = *src_ip;
    sc->fkey.dst_ip = *dst_ip;
    sc->fkey.src_port = src_port;
    sc->fkey.dst_port = dst_port;
    sc->fkey.proto = IPPROTO_UDP;

    struct traffic_info_t *flow = bpf_map_lookup_elem(&active_traffic, &sc->fkey);
    if (!flow) return 0;

    __u64 flow_age = (now > flow->flow_start_time) ? (now - flow->flow_start_time) : 0;
    if (flow_age > 5000000000ULL && flow->packets > 10) {
        return 1;
    }
    return 0;
}

// Check if a TCP packet belongs to an observed legitimate handshake / bidirectional flow
static __always_inline int is_legitimate_tcp_flow(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, const struct cyrenus_ip *dst_ip,
    __u16 src_port, __u16 dst_port
) {
    if (!sc) return 0;
    __builtin_memset(&sc->fkey, 0, sizeof(sc->fkey));
    sc->fkey.src_ip = *src_ip;
    sc->fkey.dst_ip = *dst_ip;
    sc->fkey.src_port = src_port;
    sc->fkey.dst_port = dst_port;
    sc->fkey.proto = IPPROTO_TCP;

    struct traffic_info_t *fwd = bpf_map_lookup_elem(&active_traffic, &sc->fkey);
    if (fwd && fwd->syn_count > 0) {
        return 1;
    }

    __builtin_memset(&sc->rev_fkey, 0, sizeof(sc->rev_fkey));
    sc->rev_fkey.src_ip = *dst_ip;
    sc->rev_fkey.dst_ip = *src_ip;
    sc->rev_fkey.src_port = dst_port;
    sc->rev_fkey.dst_port = src_port;
    sc->rev_fkey.proto = IPPROTO_TCP;

    struct traffic_info_t *rev = bpf_map_lookup_elem(&active_traffic, &sc->rev_fkey);
    if (rev && (rev->syn_count > 0 || fwd != NULL)) {
        return 1;
    }
    return 0;
}

static __always_inline int check_ip_list(void *map, const struct cyrenus_ip *ip) {
    struct ip_list_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.prefixlen = 128;
    key.ip = *ip;
    __u8 *val = bpf_map_lookup_elem(map, &key);
    return (val && *val == 1) ? 1 : 0;
}

// Returns ACTION_DROP (1), ACTION_PASS (2), or ACTION_NONE (0)
static __always_inline int apply_rule_for_ip(const struct cyrenus_ip *ip, __u16 port, __u8 proto) {
    struct rule_key_t key;
    struct rule_t *rule;

    // 1. Exact IP + Port + Proto
    if (port != 0 && proto != 0) {
        __builtin_memset(&key, 0, sizeof(key));
        key.ip = *ip;
        key.port = bpf_htons(port);
        key.proto = proto;
        rule = bpf_map_lookup_elem(&rules, &key);
        if (rule) return rule->action;
    }

    // 2. Wildcard Port (0) + Exact Proto
    if (proto != 0) {
        __builtin_memset(&key, 0, sizeof(key));
        key.ip = *ip;
        key.port = 0;
        key.proto = proto;
        rule = bpf_map_lookup_elem(&rules, &key);
        if (rule) return rule->action;
    }

    // 3. Exact Port + Wildcard Proto (0)
    if (port != 0) {
        __builtin_memset(&key, 0, sizeof(key));
        key.ip = *ip;
        key.port = bpf_htons(port);
        key.proto = 0;
        rule = bpf_map_lookup_elem(&rules, &key);
        if (rule) return rule->action;
    }

    // 4. Wildcard Port (0) + Wildcard Proto (0)
    __builtin_memset(&key, 0, sizeof(key));
    key.ip = *ip;
    key.port = 0;
    key.proto = 0;
    rule = bpf_map_lookup_elem(&rules, &key);
    if (rule) return rule->action;

    return ACTION_NONE;
}

static __always_inline int is_udp_amp_port(__u16 port) {
    return (port == PORT_DNS || port == PORT_NTP || port == PORT_CHARGEN ||
            port == PORT_SNMP || port == PORT_CLDAP || port == PORT_SSDP ||
            port == PORT_MEMCACHED);
}

// Returns DROP_REASON_NONE (0) or DROP_REASON_DNS / DROP_REASON_AMP
static __always_inline __u8 check_udp_amplification(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, const struct cyrenus_ip *dst_ip,
    __u16 src_port, __u16 dst_port,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now, int is_established
) {
    if (!is_udp_amp_port(src_port) && !is_udp_amp_port(dst_port)) {
        return DROP_REASON_NONE;
    }

    int is_dns = (src_port == PORT_DNS || dst_port == PORT_DNS) ? 1 : 0;
    __u32 max_dns = cfg->max_dns_response_size > 0 ? cfg->max_dns_response_size : DEFAULT_MAX_DNS_RESP_SIZE;

    // Immediate oversized reflection payload checks
    if (src_port == PORT_DNS && pkt_len > max_dns) {
        record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_DNS_AMP, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return DROP_REASON_DNS;
    }
    if ((src_port == PORT_NTP || dst_port == PORT_NTP) && pkt_len > 1024) {
        record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_UDP_AMP, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return DROP_REASON_AMP;
    }
    if ((src_port == PORT_MEMCACHED || dst_port == PORT_MEMCACHED) && pkt_len > 1400) {
        record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_UDP_AMP, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return DROP_REASON_AMP;
    }
    if ((src_port == PORT_CHARGEN || src_port == PORT_SNMP || src_port == PORT_CLDAP || src_port == PORT_SSDP) &&
        pkt_len > 1024) {
        record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_UDP_AMP, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return DROP_REASON_AMP;
    }

    struct dns_info *info = bpf_map_lookup_elem(&dns_track_map, src_ip);
    if (!info) {
        struct dns_info new_info;
        __builtin_memset(&new_info, 0, sizeof(new_info));
        new_info.last_update = now;
        new_info.packet_count = 1;
        new_info.total_size = (__u32)pkt_len;
        bpf_map_update_elem(&dns_track_map, src_ip, &new_info, BPF_ANY);
        return DROP_REASON_NONE;
    }

    __u64 elapsed = (now > info->last_update) ? (now - info->last_update) : 0;
    if (elapsed >= 1000000000ULL) {
        info->last_update = now;
        info->packet_count = 1;
        info->total_size = (__u32)pkt_len;
        return DROP_REASON_NONE;
    }

    __sync_fetch_and_add(&info->packet_count, 1);
    __sync_fetch_and_add(&info->total_size, (__u32)pkt_len);

    __u32 threshold = cfg->dns_amp_rate;
    if (is_established) {
        threshold = cfg->dns_amp_rate * 5;
    }
    __u32 min_burst = threshold / 10;
    if (min_burst < 10) min_burst = 10;
    if (min_burst > 100) min_burst = 100;

    __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
    __u32 pps = (__u32)(((__u64)info->packet_count * 1000000000ULL) / denom);

    if (info->packet_count > threshold ||
        (elapsed >= 100000000ULL && info->packet_count >= min_burst && pps > threshold)) {
        if (is_dns) {
            record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_DNS_AMP,
                          info->packet_count, info->total_size, pkt_len, pps, cfg, 1, now);
            return DROP_REASON_DNS;
        } else {
            record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_UDP_AMP,
                          info->packet_count, info->total_size, pkt_len, pps, cfg, 1, now);
            return DROP_REASON_AMP;
        }
    }

    return DROP_REASON_NONE;
}

static __always_inline __u8 check_udp_flood(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now, int is_established
) {
    struct udp_flood_info *info = bpf_map_lookup_elem(&udp_flood_map, src_ip);
    if (!info) {
        struct udp_flood_info new_info;
        __builtin_memset(&new_info, 0, sizeof(new_info));
        new_info.last_update = now;
        new_info.packet_count = 1;
        new_info.byte_count = (__u32)pkt_len;
        bpf_map_update_elem(&udp_flood_map, src_ip, &new_info, BPF_ANY);
        return DROP_REASON_NONE;
    }

    __u64 time_diff = (now > info->last_update) ? (now - info->last_update) : 0;
    if (time_diff >= 1000000000ULL) {
        info->packet_count = 1;
        info->byte_count = (__u32)pkt_len;
        info->last_update = now;
        return DROP_REASON_NONE;
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

    if (info->packet_count > threshold ||
        (time_diff >= 100000000ULL && info->packet_count >= min_burst && pps > threshold)) {
        record_attack(sc, src_ip, IPPROTO_UDP, ATK_ID_UDP_FLOOD,
                      info->packet_count, info->byte_count, pkt_len, (__u32)pps, cfg, 1, now);
        return DROP_REASON_UDP;
    }

    return DROP_REASON_NONE;
}

static __always_inline __u8 check_tcp_floods(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, const struct cyrenus_ip *dst_ip,
    __u16 src_port, __u16 dst_port, __u8 tcp_flags,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    int syn = (tcp_flags & 0x02) != 0;
    int ack = (tcp_flags & 0x10) != 0;
    int rst = (tcp_flags & 0x04) != 0;
    int fin = (tcp_flags & 0x01) != 0;

    int is_pure_syn = (syn && !ack);
    int is_synack = (syn && ack);
    int is_rst = rst;
    int is_blind_ack = 0;

    if (!syn && !rst && (ack || fin)) {
        if (!is_legitimate_tcp_flow(sc, src_ip, dst_ip, src_port, dst_port)) {
            is_blind_ack = 1;
        }
    }

    if (!is_pure_syn && !is_synack && !is_rst && !is_blind_ack) {
        return DROP_REASON_NONE;
    }

    struct syn_flood_info *info = bpf_map_lookup_elem(&syn_flood_map, src_ip);
    if (!info) {
        struct syn_flood_info new_info;
        __builtin_memset(&new_info, 0, sizeof(new_info));
        new_info.last_update = now;
        new_info.window_bytes = pkt_len;
        if (is_pure_syn) new_info.syn_count = 1;
        else if (is_synack) new_info.synack_count = 1;
        else if (is_rst) new_info.rst_count = 1;
        else if (is_blind_ack) new_info.ack_fin_count = 1;
        bpf_map_update_elem(&syn_flood_map, src_ip, &new_info, BPF_ANY);
        return DROP_REASON_NONE;
    }

    __u64 elapsed = (now > info->last_update) ? (now - info->last_update) : 0;
    if (elapsed >= 1000000000ULL) {
        info->last_update = now;
        info->window_bytes = pkt_len;
        info->syn_count = is_pure_syn ? 1 : 0;
        info->synack_count = is_synack ? 1 : 0;
        info->rst_count = is_rst ? 1 : 0;
        info->ack_fin_count = is_blind_ack ? 1 : 0;
        return DROP_REASON_NONE;
    }

    __sync_fetch_and_add(&info->window_bytes, pkt_len);
    __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;

    if (is_pure_syn) {
        __u32 cur = __sync_fetch_and_add(&info->syn_count, 1) + 1;
        __u32 threshold = cfg->syn_flood_rate;
        __u32 min_burst = threshold / 10;
        if (min_burst < 10) min_burst = 10;
        if (min_burst > 100) min_burst = 100;
        __u64 pps = ((__u64)cur * 1000000000ULL) / denom;
        if (cur > threshold || (elapsed >= 100000000ULL && cur >= min_burst && pps > threshold)) {
            record_attack(sc, src_ip, IPPROTO_TCP, ATK_ID_SYN_FLOOD,
                          cur, info->window_bytes, pkt_len, (__u32)pps, cfg, 1, now);
            return DROP_REASON_SYN;
        }
    } else if (is_synack) {
        __u32 cur = __sync_fetch_and_add(&info->synack_count, 1) + 1;
        __u32 threshold = cfg->synack_flood_rate;
        __u32 min_burst = threshold / 10;
        if (min_burst < 10) min_burst = 10;
        if (min_burst > 100) min_burst = 100;
        __u64 pps = ((__u64)cur * 1000000000ULL) / denom;
        if (cur > threshold || (elapsed >= 100000000ULL && cur >= min_burst && pps > threshold)) {
            record_attack(sc, src_ip, IPPROTO_TCP, ATK_ID_SYNACK_FLOOD,
                          cur, info->window_bytes, pkt_len, (__u32)pps, cfg, 1, now);
            return DROP_REASON_SYN;
        }
    } else if (is_rst) {
        __u32 cur = __sync_fetch_and_add(&info->rst_count, 1) + 1;
        __u32 threshold = cfg->rst_flood_rate;
        __u32 min_burst = threshold / 10;
        if (min_burst < 10) min_burst = 10;
        if (min_burst > 100) min_burst = 100;
        __u64 pps = ((__u64)cur * 1000000000ULL) / denom;
        if (cur > threshold || (elapsed >= 100000000ULL && cur >= min_burst && pps > threshold)) {
            record_attack(sc, src_ip, IPPROTO_TCP, ATK_ID_RST_FLOOD,
                          cur, info->window_bytes, pkt_len, (__u32)pps, cfg, 1, now);
            return DROP_REASON_RST;
        }
    } else if (is_blind_ack) {
        __u32 cur = __sync_fetch_and_add(&info->ack_fin_count, 1) + 1;
        __u32 threshold = cfg->ack_flood_rate;
        __u32 min_burst = threshold / 10;
        if (min_burst < 10) min_burst = 10;
        if (min_burst > 200) min_burst = 200;
        __u64 pps = ((__u64)cur * 1000000000ULL) / denom;
        if (cur > threshold || (elapsed >= 100000000ULL && cur >= min_burst && pps > threshold)) {
            record_attack(sc, src_ip, IPPROTO_TCP, ATK_ID_ACK_FLOOD,
                          cur, info->window_bytes, pkt_len, (__u32)pps, cfg, 1, now);
            return DROP_REASON_ACK;
        }
    }

    return DROP_REASON_NONE;
}

static __always_inline __u8 check_icmp_flood(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, __u8 proto,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    __u32 rate = cfg->icmp_flood_rate > 0 ? cfg->icmp_flood_rate : DEFAULT_ICMP_FLOOD_RATE;
    struct token_bucket_t *bucket = bpf_map_lookup_elem(&token_buckets, src_ip);

    if (!bucket) {
        struct token_bucket_t new_bucket;
        __builtin_memset(&new_bucket, 0, sizeof(new_bucket));
        new_bucket.last_update = now;
        new_bucket.tokens = rate > 1 ? (rate - 1) : 0;
        bpf_map_update_elem(&token_buckets, src_ip, &new_bucket, BPF_ANY);
        return DROP_REASON_NONE;
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
        return DROP_REASON_NONE;
    }

    record_attack(sc, src_ip, proto, ATK_ID_ICMP_FLOOD,
                  rate + 1, pkt_len, pkt_len, rate, cfg, 1, now);
    return DROP_REASON_ICMP;
}

static __always_inline __u8 check_global_flood(
    struct xdp_scratch *sc,
    __u8 proto, int is_pure_syn, int is_established,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    __u32 key = 0;
    struct global_rate_state *g = bpf_map_lookup_elem(&global_rate_map, &key);
    if (!g) return DROP_REASON_NONE;

    if (g->window_start_ns == 0 || (now > g->window_start_ns && (now - g->window_start_ns) >= 1000000000ULL)) {
        g->window_start_ns = now;
        g->syn_count = is_pure_syn ? 1 : 0;
        g->syn_bytes = is_pure_syn ? pkt_len : 0;
        g->udp_count = (proto == IPPROTO_UDP && !is_established) ? 1 : 0;
        g->udp_bytes = (proto == IPPROTO_UDP && !is_established) ? pkt_len : 0;
        return DROP_REASON_NONE;
    }

    struct cyrenus_ip zero_ip;
    __builtin_memset(&zero_ip, 0, sizeof(zero_ip));

    if (is_pure_syn && cfg->global_syn_rate > 0) {
        __u32 cur = __sync_fetch_and_add(&g->syn_count, 1) + 1;
        __sync_fetch_and_add(&g->syn_bytes, pkt_len);
        if (cur > cfg->global_syn_rate) {
            __u64 elapsed = (now > g->window_start_ns) ? (now - g->window_start_ns) : 10000000ULL;
            __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
            __u32 pps = (__u32)(((__u64)cur * 1000000000ULL) / denom);
            record_attack(sc, &zero_ip, IPPROTO_TCP, ATK_ID_GLOBAL_SYN_FLOOD,
                          cur, g->syn_bytes, pkt_len, pps, cfg, 0, now);
            return DROP_REASON_SYN;
        }
    }

    if (proto == IPPROTO_UDP && !is_established && cfg->global_udp_rate > 0) {
        __u32 cur = __sync_fetch_and_add(&g->udp_count, 1) + 1;
        __sync_fetch_and_add(&g->udp_bytes, pkt_len);
        if (cur > cfg->global_udp_rate) {
            __u64 elapsed = (now > g->window_start_ns) ? (now - g->window_start_ns) : 10000000ULL;
            __u64 denom = elapsed > 10000000ULL ? elapsed : 10000000ULL;
            __u32 pps = (__u32)(((__u64)cur * 1000000000ULL) / denom);
            record_attack(sc, &zero_ip, IPPROTO_UDP, ATK_ID_GLOBAL_UDP_FLOOD,
                          cur, g->udp_bytes, pkt_len, pps, cfg, 0, now);
            return DROP_REASON_UDP;
        }
    }

    return DROP_REASON_NONE;
}

static __always_inline __u8 handle_fragment(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, __u8 proto,
    int is_frag, __u16 frag_off_units, int has_mf, __u32 ip_payload_len,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    if (!is_frag) {
        return DROP_REASON_NONE;
    }

    if (frag_off_units == 1) {
        record_attack(sc, src_ip, proto, ATK_ID_FRAG_ATTACK, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return DROP_REASON_FRAG;
    }

    if (has_mf && ip_payload_len < 16) {
        record_attack(sc, src_ip, proto, ATK_ID_FRAG_ATTACK, 1, pkt_len, pkt_len, 1, cfg, 1, now);
        return DROP_REASON_FRAG;
    }

    struct frag_info *info = bpf_map_lookup_elem(&frag_track_map, src_ip);
    if (!info) {
        struct frag_info new_info;
        __builtin_memset(&new_info, 0, sizeof(new_info));
        new_info.last_update = now;
        new_info.frag_count = 1;
        bpf_map_update_elem(&frag_track_map, src_ip, &new_info, BPF_ANY);
        return DROP_REASON_NONE;
    }

    if (now > info->last_update && (now - info->last_update) > FRAG_TIMEOUT) {
        info->frag_count = 1;
    } else {
        __sync_fetch_and_add(&info->frag_count, 1);
    }
    info->last_update = now;

    if (info->frag_count > cfg->max_frags) {
        record_attack(sc, src_ip, proto, ATK_ID_FRAG_ATTACK,
                      info->frag_count, pkt_len, pkt_len, info->frag_count, cfg, 1, now);
        return DROP_REASON_FRAG;
    }

    return DROP_REASON_NONE;
}

static __always_inline __u8 check_geoip(
    struct xdp_scratch *sc,
    const struct cyrenus_ip *src_ip, __u8 proto,
    const struct attacks_config_t *cfg, __u64 pkt_len, __u64 now
) {
    __u16 *country_code_ptr = NULL;

    if (ip_is_v4_mapped(src_ip)) {
        struct geoip_key key = {
            .prefixlen = 32,
            .ip = src_ip->addr[3]
        };
        country_code_ptr = bpf_map_lookup_elem(&geoip_map, &key);
    } else {
        struct geoip6_key key6;
        key6.prefixlen = 128;
        __builtin_memcpy(key6.ip, src_ip->addr, 16);
        country_code_ptr = bpf_map_lookup_elem(&geoip6_map, &key6);
    }

    if (!country_code_ptr) {
        return DROP_REASON_NONE;
    }

    __u16 country_code = *country_code_ptr;
    __u8 *action = bpf_map_lookup_elem(&blocked_countries, &country_code);
    if (action && *action == 1) {
        record_attack(sc, src_ip, proto, ATK_ID_GEOIP_BLOCK, 1, pkt_len, pkt_len, 1, cfg, 0, now);
        return DROP_REASON_GEO;
    }

    return DROP_REASON_NONE;
}

// --- Main XDP Program ---

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);

    // Strip up to 2 stacked VLAN tags (802.1Q / 802.1AD)
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct cyrenus_vlan_hdr *vh = l3;
            if ((void *)(vh + 1) > data_end)
                return XDP_PASS;
            h_proto = vh->h_vlan_encapsulated_proto;
            l3 = (void *)(vh + 1);
        }
    }

    int is_v4 = (h_proto == bpf_htons(ETH_P_IP));
    int is_v6 = (h_proto == bpf_htons(ETH_P_IPV6));
    if (!is_v4 && !is_v6)
        return XDP_PASS;

    __u64 pkt_len = (__u64)(data_end - data);
    __u32 zero_idx = 0;

    struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &zero_idx);
    if (stats) {
        stats->total_packets++;
        stats->total_bytes += pkt_len;
    }

    struct xdp_scratch *sc = bpf_map_lookup_elem(&scratch_map, &zero_idx);
    if (!sc)
        return XDP_PASS;

    struct cyrenus_ip src_ip = {0};
    struct cyrenus_ip dst_ip = {0};
    __u8 proto = 0;
    __u32 ip_header_length = 0;
    __u32 tot_len = 0;
    int is_frag = 0;
    int is_nonfirst_frag = 0;
    __u16 frag_off_units = 0;
    int has_mf = 0;
    __u32 ip_payload_len = 0;
    int is_bcast_mcast = 0;
    void *l4 = NULL;

    if (is_v4) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->ihl < 5)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);

        ip_header_length = ip->ihl * 4;
        if (ip_header_length < sizeof(struct iphdr) || ip_header_length > 60)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);

        if ((void *)ip + ip_header_length > data_end)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);

        if (ip->saddr == 0 || ip->daddr == 0 || ip->ttl == 0)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);

        ip_from_v4(&src_ip, ip->saddr);
        ip_from_v4(&dst_ip, ip->daddr);
        proto = ip->protocol;
        tot_len = bpf_ntohs(ip->tot_len);
        ip_payload_len = (tot_len >= ip_header_length) ? (tot_len - ip_header_length) : 0;

        __u16 frag_off = bpf_ntohs(ip->frag_off);
        __u16 frag_flags = frag_off & ~IP_OFFSET;
        frag_off_units = frag_off & IP_OFFSET;
        has_mf = (frag_flags & IP_MF) ? 1 : 0;
        is_nonfirst_frag = (frag_off_units > 0) ? 1 : 0;
        is_frag = (has_mf || is_nonfirst_frag) ? 1 : 0;

        if (ip->daddr == bpf_htonl(0xFFFFFFFF))
            is_bcast_mcast = 1;

        l4 = (void *)ip + ip_header_length;
    } else {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        if (ip6->hop_limit == 0)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);

        __builtin_memcpy(src_ip.addr, &ip6->saddr, 16);
        __builtin_memcpy(dst_ip.addr, &ip6->daddr, 16);
        if (ip6->daddr.in6_u.u6_addr8[0] == 0xFF)
            is_bcast_mcast = 1;

        __u16 v6_payload = bpf_ntohs(ip6->payload_len);
        tot_len = (__u32)sizeof(struct ipv6hdr) + (__u32)v6_payload;

        __u8 nexthdr = ip6->nexthdr;
        l4 = (void *)(ip6 + 1);

        // Bounded IPv6 extension header parser (max 4 headers)
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (nexthdr == CY_IPPROTO_HOPOPTS ||
                nexthdr == CY_IPPROTO_ROUTING ||
                nexthdr == CY_IPPROTO_DSTOPTS) {
                struct cyrenus_ipv6_opt_hdr *opt = l4;
                if ((void *)(opt + 1) > data_end)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);
                nexthdr = opt->nexthdr;
                __u32 opt_len = ((__u32)opt->hdrlen + 1U) * 8U;
                l4 = (void *)opt + opt_len;
                if (l4 > data_end)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);
            } else if (nexthdr == CY_IPPROTO_FRAGMENT) {
                struct cyrenus_frag_hdr *fh = l4;
                if ((void *)(fh + 1) > data_end)
                    return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);
                __u16 foff = bpf_ntohs(fh->frag_off);
                is_frag = 1;
                frag_off_units = (foff >> 3) & 0x1FFF;
                has_mf = (foff & 0x0001) ? 1 : 0;
                is_nonfirst_frag = (frag_off_units > 0) ? 1 : 0;
                nexthdr = fh->nexthdr;
                l4 = (void *)(fh + 1);
            } else {
                break;
            }
        }

        proto = nexthdr;
        if (l4 >= (void *)ip6) {
            ip_header_length = (__u32)((long)l4 - (long)ip6);
        } else {
            ip_header_length = sizeof(struct ipv6hdr);
        }
        ip_payload_len = (tot_len >= ip_header_length) ? (tot_len - ip_header_length) : 0;
    }

    __u64 now = bpf_ktime_get_ns();

    __u16 src_port = 0, dst_port = 0;
    __u32 l4_header_length = 0;
    __u8 tcp_flags = 0;
    int tcp_malformed = 0;
    int is_icmpv6_ndp = 0;
    int is_pure_syn = 0;
    int has_l4_ports = 0;

    if (!is_nonfirst_frag) {
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end) {
                tcp_malformed = 1;
            } else {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                __u8 doff = tcp->doff;
                tcp_flags = *((__u8 *)tcp + 13);
                __u8 flags6 = tcp_flags & 0x3F;
                l4_header_length = (__u32)doff * 4U;

                if (doff < 5 || (void *)tcp + l4_header_length > data_end) {
                    tcp_malformed = 1;
                } else if (flags6 == 0 ||                    /* NULL */
                           (flags6 & 0x03) == 0x03 ||        /* SYN+FIN */
                           (flags6 & 0x06) == 0x06 ||        /* SYN+RST */
                           ((flags6 & 0x29) == 0x29 && !(flags6 & 0x10))) { /* Un-ACKed Xmas */
                    tcp_malformed = 1;
                }
                is_pure_syn = (tcp->syn && !tcp->ack) ? 1 : 0;
                has_l4_ports = 1;
            }
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
                l4_header_length = sizeof(struct udphdr);
                has_l4_ports = 1;
            }
        } else if (proto == IPPROTO_ICMP) {
            struct icmphdr *icmp = l4;
            if ((void *)(icmp + 1) <= data_end) {
                src_port = icmp->type;
                dst_port = icmp->code;
                l4_header_length = sizeof(struct icmphdr);
            }
        } else if (proto == IPPROTO_ICMPV6) {
            struct cyrenus_icmp6_hdr *icmp6 = l4;
            if ((void *)(icmp6 + 1) <= data_end) {
                src_port = icmp6->icmp6_type;
                dst_port = icmp6->icmp6_code;
                l4_header_length = sizeof(struct cyrenus_icmp6_hdr);
                if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 136) {
                    is_icmpv6_ndp = 1;
                }
            }
        }
    }

    // 1. Whitelist check (LPM IP list or explicit PASS firewall rule)
    int is_whitelisted = check_ip_list(&ip_whitelist, &src_ip);

    if (!is_whitelisted) {
        int src_rule = apply_rule_for_ip(&src_ip, src_port, proto);
        if (src_rule == ACTION_DROP)
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);
        if (src_rule == ACTION_PASS)
            is_whitelisted = 1;

        if (!is_whitelisted) {
            int dst_rule = apply_rule_for_ip(&dst_ip, dst_port, proto);
            if (dst_rule == ACTION_DROP)
                return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);
            if (dst_rule == ACTION_PASS)
                is_whitelisted = 1;
        }
    }

    // 2. Explicit IP Blacklist check
    if (!is_whitelisted && check_ip_list(&ip_blacklist, &src_ip)) {
        return xdp_drop_stats(stats, pkt_len, DROP_REASON_RULE);
    }

    // 3. Dynamic Mitigation & Flood Checks (skipped for explicitly whitelisted IPs)
    if (!is_whitelisted) {
        // 3a. Active Auto-Block Check (skip for ICMPv6 Neighbor/Router Discovery so ND never breaks)
        if (!is_icmpv6_ndp) {
            struct auto_block_val *ab = bpf_map_lookup_elem(&auto_block_map, &src_ip);
            if (ab) {
                if (now < ab->blocked_until_ns) {
                    __sync_fetch_and_add(&ab->blocked_packets, 1);
                    __sync_fetch_and_add(&ab->blocked_bytes, pkt_len);
                    ab->last_seen_ns = now;

                    struct active_attack_key akey;
                    __builtin_memset(&akey, 0, sizeof(akey));
                    akey.src_ip = src_ip;
                    akey.attack_id = ab->attack_id;
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
        }

        struct attacks_config_t cfg;
        get_config(&cfg);

        // 3b. GeoIP Country Block
        if (!is_icmpv6_ndp) {
            __u8 reason = check_geoip(sc, &src_ip, proto, &cfg, pkt_len, now);
            if (reason != DROP_REASON_NONE)
                return xdp_drop_stats(stats, pkt_len, reason);
        }

        // 3c. Malformed TCP sanity drops
        if (tcp_malformed) {
            record_attack(sc, &src_ip, IPPROTO_TCP, ATK_ID_MALFORMED_PKT, 1, pkt_len, pkt_len, 1, &cfg, 0, now);
            return xdp_drop_stats(stats, pkt_len, DROP_REASON_MALFORMED);
        }

        // 3d. IP Fragmentation Attacks (IPv4 & IPv6 Fragment Header)
        {
            __u8 reason = handle_fragment(sc, &src_ip, proto, is_frag, frag_off_units,
                                          has_mf, ip_payload_len, &cfg, pkt_len, now);
            if (reason != DROP_REASON_NONE)
                return xdp_drop_stats(stats, pkt_len, reason);
        }

        // 3e. Protocol-specific + Global Aggregate Flood Detection
        if (!is_nonfirst_frag) {
            if (proto == IPPROTO_TCP && has_l4_ports) {
                __u8 reason = check_tcp_floods(sc, &src_ip, &dst_ip, src_port, dst_port,
                                               tcp_flags, &cfg, pkt_len, now);
                if (reason != DROP_REASON_NONE)
                    return xdp_drop_stats(stats, pkt_len, reason);

                reason = check_global_flood(sc, proto, is_pure_syn, 0, &cfg, pkt_len, now);
                if (reason != DROP_REASON_NONE)
                    return xdp_drop_stats(stats, pkt_len, reason);
            } else if (proto == IPPROTO_UDP && has_l4_ports) {
                int est = is_established_udp_flow(sc, &src_ip, &dst_ip, src_port, dst_port, now);
                __u8 reason = check_udp_amplification(sc, &src_ip, &dst_ip, src_port, dst_port,
                                                      &cfg, pkt_len, now, est);
                if (reason != DROP_REASON_NONE)
                    return xdp_drop_stats(stats, pkt_len, reason);

                reason = check_udp_flood(sc, &src_ip, &cfg, pkt_len, now, est);
                if (reason != DROP_REASON_NONE)
                    return xdp_drop_stats(stats, pkt_len, reason);

                reason = check_global_flood(sc, proto, 0, est, &cfg, pkt_len, now);
                if (reason != DROP_REASON_NONE)
                    return xdp_drop_stats(stats, pkt_len, reason);
            } else if ((proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) && !is_bcast_mcast && !is_icmpv6_ndp) {
                __u8 reason = check_icmp_flood(sc, &src_ip, proto, &cfg, pkt_len, now);
                if (reason != DROP_REASON_NONE)
                    return xdp_drop_stats(stats, pkt_len, reason);
            }
        }
    }

    // 4. Record active traffic flow statistics for passed packets
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        __u32 payload_length = 0;
        if (tot_len >= ip_header_length + l4_header_length) {
            payload_length = tot_len - ip_header_length - l4_header_length;
        }

        __u8 *is_local_dst = bpf_map_lookup_elem(&host_ips, &dst_ip);
        __u8 direction = (is_local_dst != NULL) ? DIRECTION_INCOMING : DIRECTION_OUTGOING;

        __builtin_memset(&sc->fkey, 0, sizeof(sc->fkey));
        sc->fkey.src_ip = src_ip;
        sc->fkey.dst_ip = dst_ip;
        sc->fkey.src_port = src_port;
        sc->fkey.dst_port = dst_port;
        sc->fkey.proto = proto;

        struct traffic_info_t *info = bpf_map_lookup_elem(&active_traffic, &sc->fkey);
        if (!info) {
            __builtin_memset(&sc->flow, 0, sizeof(sc->flow));
            sc->flow.src_ip = src_ip;
            sc->flow.dst_ip = dst_ip;
            sc->flow.src_port = src_port;
            sc->flow.dst_port = dst_port;
            sc->flow.timestamp = now;
            sc->flow.direction = direction;
            sc->flow.ip_version = is_v6 ? 6 : 4;
            sc->flow.proto = proto;
            sc->flow.bytes = payload_length;
            sc->flow.packets = 1;
            sc->flow.flow_start_time = now;
            sc->flow.flow_end_time = now;
            sc->flow.fwd_packets = 1;
            sc->flow.fwd_bytes = payload_length;
            sc->flow.fwd_header_length = ip_header_length + l4_header_length;
            update_packet_length_stats(&sc->flow, payload_length, 0);
            if (proto == IPPROTO_TCP) {
                sc->flow.fin_count = (tcp_flags & 0x01) ? 1 : 0;
                sc->flow.syn_count = (tcp_flags & 0x02) ? 1 : 0;
                sc->flow.rst_count = (tcp_flags & 0x04) ? 1 : 0;
                sc->flow.psh_count = (tcp_flags & 0x08) ? 1 : 0;
                sc->flow.ack_count = (tcp_flags & 0x10) ? 1 : 0;
                sc->flow.urg_count = (tcp_flags & 0x20) ? 1 : 0;
                sc->flow.cwe_count = (tcp_flags & 0x40) ? 1 : 0;
                sc->flow.ece_count = (tcp_flags & 0x80) ? 1 : 0;
            }
            bpf_map_update_elem(&active_traffic, &sc->fkey, &sc->flow, BPF_ANY);
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
