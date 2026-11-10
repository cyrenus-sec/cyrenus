#include "../include/attack_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

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
        attack_id == ATK_ID_FRAG_ATTACK ||
        peak_pps >= 2000 ||
        packets >= 10000) {
        return 3; // High
    }
    if (attack_id == ATK_ID_GEOIP_BLOCK || peak_pps >= 200 || packets >= 500) {
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
    char src_ip_str[32] = {0};
    if (attack->src_ip == 0) {
        snprintf(src_ip_str, sizeof(src_ip_str), "0.0.0.0 (Global)");
    } else {
        inet_ntop(AF_INET, &(attack->src_ip), src_ip_str, INET_ADDRSTRLEN);
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
