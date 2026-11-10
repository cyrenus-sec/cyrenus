#ifndef ATTACK_INFO_H
#define ATTACK_INFO_H

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "common.h"

#define MAX_DNS_PACKETS_PER_SEC DEFAULT_DNS_AMP_RATE
#define SYN_FLOOD_RATE DEFAULT_SYN_FLOOD_RATE

struct udp_flood_info {
    uint64_t last_update;
    uint32_t packet_count;
    uint32_t byte_count;
};

struct dns_info {
    uint64_t last_update;
    uint32_t packet_count;
    uint32_t total_size;
};

struct syn_flood_info {
    uint64_t last_update;
    uint32_t syn_count;
    uint32_t synack_count;
    uint64_t syn_bytes;
};

struct active_attack_entry {
    struct active_attack_key key;
    struct active_attack_val val;
};

int get_attack_info(struct attack_info **attacks, int map_fd_attack_info_array, int map_fd_attack_count);
int get_active_attacks(struct active_attack_entry **entries, int map_fd_active_attacks);

const char *get_proto_name(uint8_t proto);
const char *get_attack_name_by_id(uint8_t attack_id);
int get_attack_severity(uint8_t attack_id, uint32_t peak_pps, uint32_t packets);
void print_attack_info(struct attack_info *attack);

#endif // ATTACK_INFO_H
