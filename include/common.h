#ifndef COMMON_H
#define COMMON_H

#if defined(__KERNEL__) || defined(__bpf__)
#include <linux/types.h>
#else
#include <linux/types.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <time.h>
#endif

#define MAX_RULES 1024
#define MAX_TRAFFIC_ENTRIES 10240
#define MAX_ATTACKS 1000
#define ATTACK_TYPE_MAX_LEN 64

// Action values for rules
#define ACTION_NONE 0
#define ACTION_DROP 1
#define ACTION_PASS 2
#define ACTION_TX   3

// Direction values
#define DIRECTION_INCOMING 0
#define DIRECTION_OUTGOING 1

// Attack IDs (shared between eBPF kernel space and user space)
#define ATK_ID_UDP_FLOOD        1
#define ATK_ID_SYN_FLOOD        2
#define ATK_ID_DNS_AMP          3
#define ATK_ID_ICMP_FLOOD       4
#define ATK_ID_FRAG_ATTACK      5
#define ATK_ID_GEOIP_BLOCK      6
#define ATK_ID_GLOBAL_SYN_FLOOD 7
#define ATK_ID_GLOBAL_UDP_FLOOD 8
#define ATK_ID_UDP_AMP          9
#define ATK_ID_ACK_FLOOD        10
#define ATK_ID_RST_FLOOD        11
#define ATK_ID_SYNACK_FLOOD     12
#define ATK_ID_MALFORMED_PKT    13
#define ATK_ID_MAX              13

// Drop reason IDs for per-vector telemetry
#define DROP_REASON_NONE      0
#define DROP_REASON_UDP       1
#define DROP_REASON_SYN       2
#define DROP_REASON_ICMP      3
#define DROP_REASON_DNS       4
#define DROP_REASON_FRAG      5
#define DROP_REASON_RULE      6
#define DROP_REASON_GEO       7
#define DROP_REASON_AUTOBLOCK 8
#define DROP_REASON_AMP       9
#define DROP_REASON_ACK       10
#define DROP_REASON_RST       11
#define DROP_REASON_MALFORMED 12

// Balanced default detection and mitigation thresholds
#define DEFAULT_SYN_FLOOD_RATE      500
#define DEFAULT_UDP_FLOOD_RATE      5000
#define DEFAULT_ICMP_FLOOD_RATE     100
#define DEFAULT_DNS_AMP_RATE        200
#define DEFAULT_MAX_FRAGS           15
#define DEFAULT_AUTO_BLOCK_ENABLED  1
#define DEFAULT_AUTO_BLOCK_SEC      300
#define DEFAULT_GLOBAL_SYN_RATE     5000
#define DEFAULT_GLOBAL_UDP_RATE     25000
#define DEFAULT_MAX_DNS_RESP_SIZE   2048
#define DEFAULT_RST_FLOOD_RATE      500
#define DEFAULT_ACK_FLOOD_RATE      2500
#define DEFAULT_SYNACK_FLOOD_RATE   1000

// Unified dual-stack IPv4/IPv6 address representation (16 bytes, network order).
// IPv4 addresses are stored in ::ffff:a.b.c.d IPv4-mapped IPv6 form:
// addr[0]=0, addr[1]=0, addr[2]=htonl(0x0000ffff), addr[3]=ipv4_be.
// All-zero addr[0..3]=0 represents wildcard / global aggregate source.
struct cyrenus_ip {
    __u32 addr[4];
};

#if !defined(__KERNEL__) && !defined(__bpf__)
struct session {
    char user_id[37];    // UUID string (36 chars + null terminator)
    char session_id[37]; // UUID string
    char token[65];      // SHA256 hex (64 chars + null terminator)
    time_t expiry;
};
#endif

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

struct geoip6_key {
    __u32 prefixlen;
    __u8 ip[16];
};

struct ip_list_key {
    __u32 prefixlen;
    struct cyrenus_ip ip;
};

struct global_stats_t {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 passed_packets;
    __u64 passed_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 udp_drops;
    __u64 syn_drops;
    __u64 icmp_drops;
    __u64 dns_drops;
    __u64 frag_drops;
    __u64 rule_drops;
    __u64 geo_drops;
    __u64 autoblock_drops;
    __u64 amp_drops;
    __u64 ack_drops;
    __u64 rst_drops;
    __u64 malformed_drops;
};

struct traffic_info_t {
    struct cyrenus_ip src_ip;
    struct cyrenus_ip dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 direction;
    __u8 proto;
    __u8 ip_version;
    __u8 pad;
    __u64 timestamp;
    struct cyrenus_ip host_ip;
    __u64 bytes;
    __u32 packets;
    __u32 pad2;
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
    struct cyrenus_ip ip;
    __u16 port;
    __u8 proto;
    __u8 pad;
};

struct flow_key_t {
    struct cyrenus_ip src_ip;
    struct cyrenus_ip dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad[3]; // Padding to ensure 4-byte alignment and no holes
};

#ifdef __KERNEL__
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
    __u32 auto_block_enabled;
    __u32 auto_block_duration_sec;
    __u32 global_syn_rate;
    __u32 global_udp_rate;
    __u32 max_dns_response_size;
    __u32 rst_flood_rate;
    __u32 ack_flood_rate;
    __u32 synack_flood_rate;
    __u32 pad;
};

struct auto_block_val {
    __u64 blocked_until_ns;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 blocked_bytes;
    __u32 blocked_packets;
    __u32 peak_pps;
    __u8 attack_id;
    __u8 protocol;
    __u16 pad;
    __u32 pad2;
};

struct active_attack_key {
    struct cyrenus_ip src_ip;
    __u8 attack_id;
    __u8 pad[3];
};

struct active_attack_val {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 last_report_ns;
    __u64 bytes;
    __u64 dropped_bytes;
    __u32 packets;
    __u32 dropped_packets;
    __u32 peak_pps;
    __u8 protocol;
    __u8 blocked;
    __u16 pad;
};

struct global_rate_state {
    __u64 window_start_ns;
    __u64 syn_bytes;
    __u64 udp_bytes;
    __u32 syn_count;
    __u32 udp_count;
};

struct attack_info {
    __u64 timestamp;
    struct cyrenus_ip src_ip;
    __u32 packets;
    __u32 peak_pps;
    __u64 bytes;
    __u8 protocol;
    __u8 attack_id;
    __u8 blocked;
    __u8 padding;
    __u32 pad2;
    char attack_type[ATTACK_TYPE_MAX_LEN];
};

#endif // COMMON_H
