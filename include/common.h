#ifndef COMMON_H
#define COMMON_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <linux/if_ether.h>
#include <net/if.h>
#endif

#define MAX_RULES 1024
#define MAX_TRAFFIC_ENTRIES 10240

// Action values for rules
#define ACTION_PASS 0
#define ACTION_DROP 1

// Direction values
#define DIRECTION_INCOMING 0
#define DIRECTION_OUTGOING 1

struct session {
    char user_id[37];  // UUID string (36 chars + null terminator)
    char session_id[37];  // UUID string
    char token[65];  // SHA256 hash is 64 characters + null terminator
    time_t expiry;
};


struct rule_t {
  
    uint16_t port_start;
    uint16_t port_end;
    uint8_t proto;
    uint8_t action;
};


 
struct traffic_info_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t timestamp;
    uint8_t direction;
    uint32_t host_ip;
    uint8_t proto;
    uint64_t bytes;
    uint32_t packets;
    uint64_t flow_start_time;
    uint64_t flow_end_time;
    uint32_t fwd_packets;
    uint32_t bwd_packets;
    uint64_t fwd_bytes;
    uint64_t bwd_bytes;
    uint32_t fwd_header_length;
    uint32_t bwd_header_length;
    uint16_t min_packet_length;
    uint16_t max_packet_length;
    uint32_t fwd_packet_length_max;
    uint32_t fwd_packet_length_min;
    uint32_t fwd_packet_length_sum;
    uint32_t bwd_packet_length_max;
    uint32_t bwd_packet_length_min;
    uint32_t bwd_packet_length_sum;
    uint32_t iat_sum;
    uint32_t fwd_iat_sum;
    uint32_t bwd_iat_sum;
    uint32_t fin_count;
    uint32_t syn_count;
    uint32_t rst_count;
    uint32_t psh_count;
    uint32_t ack_count;
    uint32_t urg_count;
    uint32_t cwe_count;
    uint32_t ece_count;
};
struct rule_key_t {
    __u32 ip;
    __u16 port;
    __u8 proto;
};
// Action values for rules
#define ACTION_PASS 0
#define ACTION_DROP 1

// Direction values
#define DIRECTION_INCOMING 0
#define DIRECTION_OUTGOING 1

#ifdef __KERNEL__
// XDP action values for kernel space
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#endif

#endif // COMMON_H