#include "../include/attack_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

bool cyrenus_ip_is_zero(const struct cyrenus_ip *ip) {
    if (!ip) return true;
    return (ip->addr[0] | ip->addr[1] | ip->addr[2] | ip->addr[3]) == 0;
}

bool cyrenus_ip_is_v4(const struct cyrenus_ip *ip) {
    if (!ip) return false;
    return (ip->addr[0] == 0 && ip->addr[1] == 0 && ip->addr[2] == htonl(0x0000ffff));
}

bool cyrenus_ip_equals(const struct cyrenus_ip *a, const struct cyrenus_ip *b) {
    if (!a || !b) return false;
    return memcmp(a->addr, b->addr, sizeof(a->addr)) == 0;
}

void cyrenus_ip_from_v4(struct cyrenus_ip *out, uint32_t ipv4_be) {
    if (!out) return;
    out->addr[0] = 0;
    out->addr[1] = 0;
    out->addr[2] = htonl(0x0000ffff);
    out->addr[3] = ipv4_be;
}

void cyrenus_ip_from_v6(struct cyrenus_ip *out, const struct in6_addr *in6) {
    if (!out || !in6) return;
    memcpy(out->addr, in6->s6_addr, 16);
}

int cyrenus_str_to_ip(const char *str, struct cyrenus_ip *out, int *af_out) {
    if (!str || str[0] == '\0' || !out) return -1;

    struct in_addr v4;
    if (inet_pton(AF_INET, str, &v4) == 1) {
        cyrenus_ip_from_v4(out, v4.s_addr);
        if (af_out) *af_out = AF_INET;
        return 0;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, str, &v6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&v6)) {
            uint32_t v4_be = 0;
            memcpy(&v4_be, v6.s6_addr + 12, 4);
            cyrenus_ip_from_v4(out, v4_be);
            if (af_out) *af_out = AF_INET;
        } else {
            cyrenus_ip_from_v6(out, &v6);
            if (af_out) *af_out = AF_INET6;
        }
        return 0;
    }

    return -1;
}

void cyrenus_ip_to_str(const struct cyrenus_ip *ip, char *buf, size_t len) {
    if (!buf || len == 0) return;
    if (!ip || cyrenus_ip_is_zero(ip)) {
        snprintf(buf, len, "0.0.0.0");
        return;
    }
    if (cyrenus_ip_is_v4(ip)) {
        struct in_addr a = { .s_addr = ip->addr[3] };
        if (!inet_ntop(AF_INET, &a, buf, (socklen_t)len)) {
            snprintf(buf, len, "0.0.0.0");
        }
        return;
    }
    if (!inet_ntop(AF_INET6, ip->addr, buf, (socklen_t)len)) {
        snprintf(buf, len, "::");
    }
}

int cyrenus_parse_cidr(const char *input, int explicit_cidr,
                       char canonical_ip[46], uint8_t *cidr_out,
                       struct cyrenus_ip *masked_out, int *af_out) {
    if (!input || input[0] == '\0' || !canonical_ip || !cidr_out || !masked_out) {
        return -1;
    }

    char ip_buf[80] = {0};
    snprintf(ip_buf, sizeof(ip_buf), "%s", input);

    int has_slash = 0;
    int parsed_cidr = explicit_cidr;
    char *slash = strchr(ip_buf, '/');
    if (slash) {
        *slash = '\0';
        const char *cidr_str = slash + 1;
        if (*cidr_str == '\0') return -1;
        char *endptr = NULL;
        long val = strtol(cidr_str, &endptr, 10);
        if (endptr == cidr_str || *endptr != '\0' || val < 1 || val > 128) {
            return -1;
        }
        parsed_cidr = (int)val;
        has_slash = 1;
    }

    struct cyrenus_ip raw_ip;
    int af = AF_INET;
    if (cyrenus_str_to_ip(ip_buf, &raw_ip, &af) != 0) {
        return -1;
    }

    if (af == AF_INET) {
        int cidr = (!has_slash && parsed_cidr <= 0) ? 32 : parsed_cidr;
        if (cidr < 1 || cidr > 32) return -1;

        uint32_t mask_host = (~0U << (32 - cidr));
        uint32_t net_ip_be = htonl(ntohl(raw_ip.addr[3]) & mask_host);
        struct in_addr net_addr = { .s_addr = net_ip_be };
        if (!inet_ntop(AF_INET, &net_addr, canonical_ip, 46)) {
            return -1;
        }
        cyrenus_ip_from_v4(masked_out, net_ip_be);
        *cidr_out = (uint8_t)cidr;
        if (af_out) *af_out = AF_INET;
        return 0;
    }

    int cidr = (!has_slash && parsed_cidr <= 0) ? 128 : parsed_cidr;
    if (cidr < 1 || cidr > 128) return -1;

    uint8_t bytes[16];
    memcpy(bytes, raw_ip.addr, 16);
    int full_bytes = cidr / 8;
    int rem_bits = cidr % 8;
    if (full_bytes < 16) {
        if (rem_bits > 0) {
            bytes[full_bytes] &= (uint8_t)(0xFFU << (8 - rem_bits));
            full_bytes++;
        }
        for (int i = full_bytes; i < 16; i++) {
            bytes[i] = 0;
        }
    }

    struct in6_addr net6;
    memcpy(net6.s6_addr, bytes, 16);
    if (!inet_ntop(AF_INET6, &net6, canonical_ip, 46)) {
        return -1;
    }
    cyrenus_ip_from_v6(masked_out, &net6);
    *cidr_out = (uint8_t)cidr;
    if (af_out) *af_out = AF_INET6;
    return 0;
}

uint32_t cyrenus_ip_to_lpm_prefix(int af, uint8_t cidr) {
    if (af == AF_INET) {
        uint8_t clamped = (cidr >= 1 && cidr <= 32) ? cidr : 32;
        return (uint32_t)(96 + clamped);
    }
    uint8_t clamped = (cidr >= 1 && cidr <= 128) ? cidr : 128;
    return (uint32_t)clamped;
}

void cyrenus_ip_to_hex(const struct cyrenus_ip *ip, char hex_out[33]) {
    static const char hex[] = "0123456789abcdef";
    const uint8_t *bytes = (const uint8_t *)ip->addr;
    if (!ip || !hex_out) return;
    for (int i = 0; i < 16; i++) {
        hex_out[i * 2] = hex[(bytes[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    hex_out[32] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int cyrenus_hex_to_ip(const char *hex, struct cyrenus_ip *out) {
    if (!hex || !out || strlen(hex) != 32) return -1;
    uint8_t bytes[16];
    for (int i = 0; i < 16; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    memcpy(out->addr, bytes, 16);
    return 0;
}

const char *get_proto_name(uint8_t proto) {
    switch (proto) {
        case 0: return "ALL";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        case IPPROTO_IPIP: return "IPIP";
        case IPPROTO_GRE: return "GRE";
        case IPPROTO_ESP: return "ESP";
        case IPPROTO_AH: return "AH";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_SCTP: return "SCTP";
        default: return "Unknown";
    }
}

const char *get_attack_name_by_id(uint8_t attack_id) {
    switch (attack_id) {
        case ATK_ID_UDP_FLOOD:        return "UDP Flood";
        case ATK_ID_SYN_FLOOD:        return "SYN Flood";
        case ATK_ID_DNS_AMP:          return "DNS Amplification";
        case ATK_ID_ICMP_FLOOD:       return "ICMP Flood";
        case ATK_ID_FRAG_ATTACK:      return "Fragment Attack";
        case ATK_ID_GEOIP_BLOCK:      return "GeoIP Block";
        case ATK_ID_GLOBAL_SYN_FLOOD: return "Distributed SYN Flood";
        case ATK_ID_GLOBAL_UDP_FLOOD: return "Distributed UDP Flood";
        case ATK_ID_UDP_AMP:          return "UDP Amplification";
        case ATK_ID_ACK_FLOOD:        return "TCP ACK Flood";
        case ATK_ID_RST_FLOOD:        return "TCP RST Flood";
        case ATK_ID_SYNACK_FLOOD:     return "SYN-ACK Reflection";
        case ATK_ID_MALFORMED_PKT:    return "Malformed Packet";
        default:                      return "Unknown Attack";
    }
}

int get_attack_severity(uint8_t attack_id, uint32_t peak_pps, uint32_t packets) {
    if (attack_id == ATK_ID_GLOBAL_SYN_FLOOD ||
        attack_id == ATK_ID_GLOBAL_UDP_FLOOD ||
        peak_pps >= 10000 ||
        packets >= 50000) {
        return 4; // Critical
    }
    if (attack_id == ATK_ID_SYN_FLOOD ||
        attack_id == ATK_ID_DNS_AMP ||
        attack_id == ATK_ID_UDP_AMP ||
        attack_id == ATK_ID_SYNACK_FLOOD ||
        attack_id == ATK_ID_RST_FLOOD ||
        attack_id == ATK_ID_ACK_FLOOD ||
        attack_id == ATK_ID_FRAG_ATTACK ||
        peak_pps >= 2000 ||
        packets >= 10000) {
        return 3; // High
    }
    if (attack_id == ATK_ID_GEOIP_BLOCK ||
        attack_id == ATK_ID_MALFORMED_PKT ||
        peak_pps >= 200 ||
        packets >= 500) {
        return 2; // Medium
    }
    return 1; // Low
}

int get_attack_info(struct attack_info **attacks, int map_fd_attack_info_array, int map_fd_attack_count) {
    (void)map_fd_attack_count;
    if (!attacks) return 0;

    *attacks = calloc(MAX_ATTACKS, sizeof(struct attack_info));
    if (!*attacks) {
        fprintf(stderr, "Failed to allocate memory for attack info\n");
        return 0;
    }

    if (map_fd_attack_info_array < 0) {
        return 0;
    }

    uint32_t attack_count = 0;
    uint32_t key = 0, next_key = 0;
    void *cur_key = NULL;
    while (bpf_map_get_next_key(map_fd_attack_info_array, cur_key, &next_key) == 0) {
        struct attack_info ebpf_attack;
        if (bpf_map_lookup_elem(map_fd_attack_info_array, &next_key, &ebpf_attack) == 0) {
            if (ebpf_attack.packets > 0 && ebpf_attack.timestamp > 0) {
                memcpy(&(*attacks)[attack_count], &ebpf_attack, sizeof(struct attack_info));
                attack_count++;
                if (attack_count >= MAX_ATTACKS) break;
            }
        }
        key = next_key;
        cur_key = &key;
    }

    return (int)attack_count;
}

int get_active_attacks(struct active_attack_entry **entries, int map_fd_active_attacks) {
    if (!entries) return 0;
    *entries = NULL;

    if (map_fd_active_attacks < 0) return 0;

    int capacity = 64;
    int count = 0;
    struct active_attack_entry *list = calloc((size_t)capacity, sizeof(struct active_attack_entry));
    if (!list) return 0;

    struct active_attack_key key = {0}, next_key = {0};
    void *cur_key = NULL;

    while (bpf_map_get_next_key(map_fd_active_attacks, cur_key, &next_key) == 0) {
        struct active_attack_val val;
        if (bpf_map_lookup_elem(map_fd_active_attacks, &next_key, &val) == 0 && val.packets > 0) {
            if (count >= capacity) {
                if (capacity >= 8192) break;
                capacity *= 2;
                struct active_attack_entry *tmp = realloc(list, sizeof(struct active_attack_entry) * (size_t)capacity);
                if (!tmp) break;
                list = tmp;
            }
            list[count].key = next_key;
            list[count].val = val;
            count++;
        }
        key = next_key;
        cur_key = &key;
    }

    *entries = list;
    return count;
}

void print_attack_info(struct attack_info *attack) {
    if (!attack) return;
    char src_ip_str[64] = {0};
    if (cyrenus_ip_is_zero(&attack->src_ip)) {
        snprintf(src_ip_str, sizeof(src_ip_str), "0.0.0.0 (Global)");
    } else {
        cyrenus_ip_to_str(&attack->src_ip, src_ip_str, sizeof(src_ip_str));
    }

    printf("Attack Type: %s\n", attack->attack_type[0] ? attack->attack_type : get_attack_name_by_id(attack->attack_id));
    printf("Timestamp: %llu\n", (unsigned long long)attack->timestamp);
    printf("Source IP: %s\n", src_ip_str);
    printf("Protocol: %s\n", get_proto_name(attack->protocol));
    printf("Packets: %u (Peak PPS: %u)\n", attack->packets, attack->peak_pps);
    printf("Bytes: %llu\n", (unsigned long long)attack->bytes);
    printf("Blocked: %s\n", attack->blocked ? "Yes" : "No");
    printf("------------------------------\n");
}
