#ifndef ATTACK_INFO_H
#define ATTACK_INFO_H

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>

#define MAX_ATTACKS 1000
#define ATTACK_TYPE_MAX_LEN 64


#define MAX_DNS_PACKETS_PER_SEC 100
#define SYN_FLOOD_RATE 100

 

struct attack_info {
 uint64_t timestamp;
    uint32_t src_ip;
    uint8_t protocol;
    char attack_type[ATTACK_TYPE_MAX_LEN];
    uint32_t packets;
    uint64_t bytes;
    uint8_t padding[4];  // Ensure 8-byte alignment
};

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
};





int get_attack_info(struct attack_info **attacks, int map_fd_attack_info_array, int map_fd_attack_count);

const char* get_proto_name(uint8_t proto);
void print_attack_info(struct attack_info *attack);

#endif // ATTACK_INFO_H