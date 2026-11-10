#ifndef ATTACK_INFO_H
#define ATTACK_INFO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
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
    uint64_t syn_bytes;
    uint32_t syn_count;
    uint32_t synack_count;
    uint32_t rst_count;
    uint32_t ack_fin_count;
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

// Shared IPv4/IPv6 <-> struct cyrenus_ip conversion utilities
bool cyrenus_ip_is_zero(const struct cyrenus_ip *ip);
bool cyrenus_ip_is_v4(const struct cyrenus_ip *ip);
bool cyrenus_ip_equals(const struct cyrenus_ip *a, const struct cyrenus_ip *b);
void cyrenus_ip_from_v4(struct cyrenus_ip *out, uint32_t ipv4_be);
void cyrenus_ip_from_v6(struct cyrenus_ip *out, const struct in6_addr *in6);
int cyrenus_str_to_ip(const char *str, struct cyrenus_ip *out, int *af_out);
void cyrenus_ip_to_str(const struct cyrenus_ip *ip, char *buf, size_t len);
int cyrenus_parse_cidr(const char *input, int explicit_cidr,
                       char canonical_ip[46], uint8_t *cidr_out,
                       struct cyrenus_ip *masked_out, int *af_out);
uint32_t cyrenus_ip_to_lpm_prefix(int af, uint8_t cidr);
void cyrenus_ip_to_hex(const struct cyrenus_ip *ip, char hex_out[33]);
int cyrenus_hex_to_ip(const char *hex, struct cyrenus_ip *out);

#endif // ATTACK_INFO_H
