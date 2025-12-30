#ifndef COMMON_H
#define COMMON_H

#if defined(__KERNEL__) || defined(__bpf__)
#include <linux/types.h>
#else
#include <linux/types.h>
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
  
    __u16 port_start;
    __u16 port_end;
    __u8 proto;
    __u8 action;
};


 
struct geoip_key {
    __u32 prefixlen;
    __u32 ip;
};

struct global_stats_t {
    __u64 total_packets;
    __u64 total_bytes;
};

struct traffic_info_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 timestamp;
    __u8 direction;
    __u32 host_ip;
    __u8 proto;
    __u64 bytes;
    __u32 packets;
    __u64 flow_start_time;
    __u64 flow_end_time;
    __u32 fwd_packets;
    __u32 bwd_packets;
    __u64 fwd_bytes;
    __u64 bwd_bytes;
    __u32 fwd_header_length;
    __u32 bwd_header_length;
    __u16 min_packet_length;
    __u16 max_packet_length;
    __u32 fwd_packet_length_max;
    __u32 fwd_packet_length_min;
    __u32 fwd_packet_length_sum;
    __u32 bwd_packet_length_max;
    __u32 bwd_packet_length_min;
    __u32 bwd_packet_length_sum;
    __u32 iat_sum;
    __u32 fwd_iat_sum;
    __u32 bwd_iat_sum;
    __u32 fin_count;
    __u32 syn_count;
    __u32 rst_count;
    __u32 psh_count;
    __u32 ack_count;
    __u32 urg_count;
    __u32 cwe_count;
    __u32 ece_count;
};
struct rule_key_t {
    __u32 ip;
    __u16 port;
    __u8 proto;
};

struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad[3]; // Padding to ensure 4-byte alignment and no holes
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


struct attacks_config_t {
    __u32 syn_flood_rate;
    __u32 udp_flood_rate;
    __u32 icmp_flood_rate;
    __u32 dns_amp_rate;
    __u32 max_frags;
};

#define ATTACK_TYPE_MAX_LEN 64

struct attack_info {
    __u64 timestamp;
    __u32 src_ip;
    __u8 protocol;
    char attack_type[ATTACK_TYPE_MAX_LEN]; 
    __u32 packets;
    __u64 bytes;
    __u8 padding[4];  // Ensure 8-byte alignment
};

#endif // COMMON_H