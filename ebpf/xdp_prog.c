#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/common.h"

#define MAX_FRAGS_PER_IP 15
#define FRAG_TIMEOUT 30000000000
#define IP_CE 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define MAX_PORTS 65536
#define MAX_PROTOCOL 256
#define TOKENS_PER_SECOND 1000
#define MAX_TOKENS 1000
#define ICMP_RATE_LIMIT 100
#define SYN_FLOOD_RATE 100
#define DNS_PORT 53
#define MAX_DNS_PACKETS_PER_SEC 100
#define MAX_DNS_RESPONSE_SIZE 512
#define UDP_FLOOD_RATE 5000000
#define UDP_FLOOD_BURST 200
#define UDP_TRACK_TIMEOUT 500000000 // 
#define MAX_ATTACKS 1000

// First, let's define our attack classification system
#define ATTACK_TYPE_UDP_FLOOD    0x0001
#define ATTACK_TYPE_SYN_FLOOD    0x0002
#define ATTACK_TYPE_DNS_AMP      0x0004
#define ATTACK_TYPE_ICMP_FLOOD   0x0008
#define ATTACK_TYPE_PORT_SCAN    0x0010
#define ATTACK_TYPE_FRAG_ATTACK  0x0020
#define ATTACK_TYPE_HTTP_FLOOD   0x0040
#define ATTACK_TYPE_SSL_ABUSE    0x0080

// Severity levels based on industry standards
#define SEVERITY_LOW       1
#define SEVERITY_MEDIUM    2
#define SEVERITY_HIGH      3
#define SEVERITY_CRITICAL  4

// Attack phases for tracking attack lifecycle
#define PHASE_INITIAL     1  // First detection
#define PHASE_ONGOING     2  // Attack continuing
#define PHASE_ESCALATING  3  // Attack intensifying
#define PHASE_MITIGATING  4  // Countermeasures active
#define PHASE_RESOLVED    5  // Attack ended


// struct attack_info defined in common.h

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats_t);
} global_stats SEC(".maps");

struct token_bucket_t {
    __u64 last_update;
    __u32 tokens;
};

struct syn_flood_info {
    __u64 last_update;
    __u32 syn_count;
    __u32 synack_count;  // Track SYN-ACK responses separately
};

struct dns_info {
    __u64 last_update;
    __u32 packet_count;
    __u32 total_size;
};

struct frag_info {
    __u64 last_update;
    __u32 frag_count;  // Changed from __u16 to __u32 for atomic operation support
};

struct udp_flood_info {
    __u64 last_update;
    __u32 packet_count;
    __u32 byte_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Fixed: Was PERCPU, causing counters to split
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct udp_flood_info);
} udp_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Fixed: Was PERCPU, causing counters to split
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct frag_info);
} frag_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Fixed: Was PERCPU, causing counters to split
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct dns_info);
} dns_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Fixed: Was PERCPU, causing counters to split
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

// GeoIP Maps
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 600000); // Sufficient for full IPv4 country coverage
    __type(key, struct geoip_key);
    __type(value, __u16); // Country Code (numeric ISO or custom ID)
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geoip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); // ISO 3166-1 numeric codes
    __type(key, __u16); // Country Code
    __type(value, __u8); // Action: 1=DROP, 0=PASS
} blocked_countries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct attacks_config_t);
} config_map SEC(".maps");

static __always_inline void get_config(struct attacks_config_t *cfg) {
    __u32 key = 0;
    struct attacks_config_t *map_cfg = bpf_map_lookup_elem(&config_map, &key);
    if (map_cfg) {
        *cfg = *map_cfg;
    } else {
        // Defaults if map not populated
        cfg->syn_flood_rate = 1000;
        cfg->udp_flood_rate = 50000;
        cfg->icmp_flood_rate = 100;
        cfg->dns_amp_rate = 200;
        cfg->max_frags = 15;
    }
}


static __always_inline void print_ip_and_pps(__u32 ip, __u64 pps)
{
    __u8 a = ip & 0xFF;
    __u8 b = (ip >> 8) & 0xFF;
    __u8 c = (ip >> 16) & 0xFF;
    __u8 d = (ip >> 24) & 0xFF;
    bpf_printk("UDP flood detected from IP: %d.%d", d, c);
    bpf_printk(".%d.%d, PPS: %llu", b, a, pps);
}

static __always_inline void update_attack_info(__u32 src_ip, __u8 protocol, __u32 packets, __u64 bytes) {
    __u32 index = 0;
    __u32 count = 0;
    
    // Lookup current attack count
    __u32 *count_ptr = bpf_map_lookup_elem(&attack_count, &index);
    if (count_ptr) {
        count = *count_ptr;
    } else {
        // If lookup fails, initialize count to 0
        count = 0;
    }

    if (count >= MAX_ATTACKS) {
        // Array is full - evict oldest entry by wrapping to last slot
        count = MAX_ATTACKS - 1;
        bpf_printk("WARN: Attack array full, evicting oldest entry");
    }

    struct attack_info new_attack = {0}; // Zero out everything first
    
    new_attack.timestamp = bpf_ktime_get_ns();
    new_attack.src_ip = src_ip;
    new_attack.protocol = protocol;
    new_attack.packets = packets;
    new_attack.bytes = bytes;
    // attack_type is zeroed out by {0}, which is fine for now. 
    // We could add logic to populate it based on type.

    // Update the attack info array
    (void)bpf_map_update_elem(&attack_info_array, &count, &new_attack, BPF_ANY);
   
    // Increment and update the attack count
    count++;
     bpf_map_update_elem(&attack_count, &index, &count, BPF_ANY);
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
    info->iat_sum += iat;

    if (direction == 0)
        info->fwd_iat_sum += iat;
    else
        info->bwd_iat_sum += iat;
}

// Helper: Check if traffic belongs to an established flow (>5 seconds old)
// Established flows get lenient treatment to avoid blocking legitimate heavy users
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
    
    // Flow is established if it's been active for >5 seconds
    __u64 flow_age = now - flow->flow_start_time;
    if (flow_age > 5000000000ULL) {  // 5 seconds in nanoseconds
        return 1;
    }
    
    return 0;
}

static __always_inline int check_udp_flood(struct iphdr *iph, struct udphdr *udph) {
    __u32 src_ip = iph->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u32 pkt_size = bpf_ntohs(iph->tot_len);

    struct udp_flood_info *info, new_info = {0};
    struct attacks_config_t cfg;
    get_config(&cfg);
    __u64 now = bpf_ktime_get_ns();

    info = bpf_map_lookup_elem(&udp_flood_map, &src_ip);
    if (!info) {
        new_info.last_update = now;
        new_info.packet_count = 1;
        new_info.byte_count = pkt_size;
        bpf_map_update_elem(&udp_flood_map, &src_ip, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    __u64 time_diff = now - info->last_update;
    
    // Reset window every second (sliding window)
    if (time_diff >= 1000000000ULL) {
        info->packet_count = 1;
        info->byte_count = pkt_size;
        info->last_update = now;
        return XDP_PASS;
    }
    
    // Within the same window - use atomic ops to prevent race conditions
    __sync_fetch_and_add(&info->packet_count, 1);
    __sync_fetch_and_add(&info->byte_count, pkt_size);

    // Only calculate PPS if we have enough data (at least 100ms)
    // This prevents false positives from instantaneous bursts
    if (time_diff > 100000000ULL) {
        // Prevent division by zero
        if (time_diff == 0) return XDP_PASS;
        
        __u64 pps = (info->packet_count * 1000000000ULL) / time_diff;

        // Check if this belongs to an established flow
        int is_established = is_established_flow(src_ip, iph->daddr, 
                                                   src_port, dst_port, 
                                                   IPPROTO_UDP, now);
        
        __u64 threshold = cfg.udp_flood_rate;
        if (is_established) {
            // Established flows get 10x lenient threshold
            // This allows legitimate heavy users (file downloads, video calls)
            threshold = cfg.udp_flood_rate * 10;
        }

        if (pps > threshold && info->packet_count > UDP_FLOOD_BURST) {
            if (is_established) {
                bpf_printk("UDP flood on ESTABLISHED flow from IP 0x%x, PPS: %llu", 
                          bpf_ntohl(src_ip), pps);
            } else {
                bpf_printk("UDP flood detected from IP 0x%x, PPS: %llu", 
                          bpf_ntohl(src_ip), pps);
            }
           
            update_attack_info(src_ip, IPPROTO_UDP, 1, pkt_size);
            print_ip_and_pps(src_ip ,pps );
            return XDP_DROP;
        }
    }

    info->last_update = now;

    if (dst_port == 53 && pkt_size > 512) {
        bpf_printk("Large DNS query detected from IP 0x%x", bpf_ntohl(src_ip));
        return XDP_DROP;
    }

    if ((dst_port == 123 || src_port == 123) && pkt_size > 1024) {
        bpf_printk("Large NTP packet detected from IP 0x%x", bpf_ntohl(src_ip));
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int check_dns_amplification(struct iphdr *iph, struct udphdr *udph, int is_response) {
    __u32 src_ip = iph->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u32 packet_size = bpf_ntohs(iph->tot_len);

    if (src_port != DNS_PORT && dst_port != DNS_PORT) {
        return XDP_PASS;
    }

    struct dns_info *info, new_info = {0};
    struct attacks_config_t cfg;
    get_config(&cfg);
    info = bpf_map_lookup_elem(&dns_track_map, &src_ip);

    if (!info) {
        new_info.last_update = bpf_ktime_get_ns();
        new_info.packet_count = 1;
        new_info.total_size = packet_size;
        bpf_map_update_elem(&dns_track_map, &src_ip, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - info->last_update;

    if (elapsed < 1000000000) {
        __sync_fetch_and_add(&info->packet_count, 1);
        __sync_fetch_and_add(&info->total_size, packet_size);

        // Check if this is an established DNS server flow
        int is_established = is_established_flow(src_ip, iph->daddr,
                                                   src_port, dst_port,
                                                   IPPROTO_UDP, now);
        
        __u32 threshold = cfg.dns_amp_rate;
        if (is_established) {
            // Established DNS servers get 5x lenient threshold
            // This allows legitimate authoritative DNS servers
            threshold = cfg.dns_amp_rate * 5;
        }

        if (info->packet_count > threshold) {
            if (is_established) {
                bpf_printk("DNS rate limit exceeded for ESTABLISHED flow from IP 0x%x", 
                          bpf_ntohl(src_ip));
            } else {
                bpf_printk("DNS rate limit exceeded for IP 0x%x", bpf_ntohl(src_ip));
            }
            return XDP_DROP;
        }

        if (is_response && packet_size > MAX_DNS_RESPONSE_SIZE) {
            bpf_printk("Large DNS response detected from IP 0x%x", bpf_ntohl(src_ip));
            return XDP_DROP;
        }
    } else {
        info->last_update = now;
        info->packet_count = 1;
        info->total_size = packet_size;
    }

    return XDP_PASS;
}

static __always_inline int handle_fragment(struct iphdr *iph) {
    __u32 src_ip = iph->saddr;
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    __u16 frag_flags = frag_off & ~IP_OFFSET;
    __u16 frag_offset = frag_off & IP_OFFSET;

    if ((frag_flags & IP_MF) || frag_offset > 0) {
        struct frag_info *info, new_info = {0};
        struct attacks_config_t cfg;
        get_config(&cfg);
        __u64 now = bpf_ktime_get_ns();

        info = bpf_map_lookup_elem(&frag_track_map, &src_ip);
        if (!info) {
            new_info.last_update = now;
            new_info.frag_count = 1;
            bpf_map_update_elem(&frag_track_map, &src_ip, &new_info, BPF_ANY);
        } else {
            if (now - info->last_update > FRAG_TIMEOUT) {
                info->frag_count = 1;
            } else {
                __sync_fetch_and_add(&info->frag_count, 1);
            }
            info->last_update = now;

            if (info->frag_count > cfg.max_frags) {
                bpf_printk("Too many fragments from IP 0x%x", bpf_ntohl(src_ip));
                return XDP_DROP;
            }
        }

        if (frag_offset == 1) {
            bpf_printk("Tiny fragment detected from IP 0x%x", bpf_ntohl(src_ip));
            return XDP_DROP;
        }

        __u16 ip_payload_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4);
        if ((frag_flags & IP_MF) && ip_payload_len < 16) {
            bpf_printk("Suspicious small fragment from IP 0x%x", bpf_ntohl(src_ip));
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

 static __always_inline int apply_rule(__u32 ip, __u16 port, __u8 proto) {
    struct rule_key_t key = {
        .ip = ip,
        .port = bpf_htons(port),
        .proto = proto
    };

    // First check: exact match (IP + specific port + proto)
    struct rule_t *rule = bpf_map_lookup_elem(&rules, &key);
    if (rule) {
        bpf_printk("Exact match: ip=0x%x, port=%u, proto=%u", bpf_ntohl(ip), port, proto);
        if (rule->action == 1) {
            return XDP_DROP;
        } else if (rule->action == 2) {
            return XDP_PASS;
        } else if (rule->action == 3) {
            return XDP_TX;
        } else {
            return XDP_PASS;
        }
    }
    
    // Second check: wildcard port (port 0 = match any port)
    // This allows blocking all traffic from an IP by setting rule with port=0
    key.port = 0;
    rule = bpf_map_lookup_elem(&rules, &key);
    if (rule) {
        bpf_printk("Wildcard port match: ip=0x%x, any_port (actual=%u), proto=%u", 
                  bpf_ntohl(ip), port, proto);
        if (rule->action == 1) {
            return XDP_DROP;
        } else if (rule->action == 2) {
            return XDP_PASS;
        } else if (rule->action == 3) {
            return XDP_TX;
        } else {
            return XDP_PASS;
        }
    }
    
    return XDP_PASS;
}

static __always_inline int check_syn_flood(struct iphdr *iph, struct tcphdr *tcph) {
    // Track both SYN and SYN-ACK to differentiate attacks from server responses
    if (tcph->syn) {
        struct syn_flood_info *info, new_info = {0};
        __u32 src_ip = iph->saddr;
        
        info = bpf_map_lookup_elem(&syn_flood_map, &src_ip);
        if (!info) {
            new_info.last_update = bpf_ktime_get_ns();
            if (tcph->ack) {
                new_info.synack_count = 1;
            } else {
                new_info.syn_count = 1;
            }
            bpf_map_update_elem(&syn_flood_map, &src_ip, &new_info, BPF_ANY);
            return XDP_PASS;
        }

        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - info->last_update;
        
        struct attacks_config_t cfg;
        get_config(&cfg);

        if (elapsed < 1000000000) {
            // Within 1 second window - increment appropriate counter (atomic for concurrent access)
            if (tcph->ack) {
                __sync_fetch_and_add(&info->synack_count, 1);
            } else {
                __sync_fetch_and_add(&info->syn_count, 1);
                
                // Only flag if SYN count is excessive AND far exceeds SYN-ACK
                // This prevents blocking legitimate servers sending SYN-ACK responses
                if (info->syn_count > cfg.syn_flood_rate && 
                    info->syn_count > info->synack_count * 10) {
                    bpf_printk("SYN flood detected from IP 0x%x (SYN:%u SYNACK:%u)", 
                              bpf_ntohl(src_ip), info->syn_count, info->synack_count);
                    return XDP_DROP;
                }
            }
        } else {
            // Reset window
            info->last_update = now;
            if (tcph->ack) {
                info->synack_count = 1;
                info->syn_count = 0;
            } else {
                info->syn_count = 1;
                info->synack_count = 0;
            }
        }
    }
    return XDP_PASS;
}

static __always_inline int early_filter(struct iphdr *iph, __u8 proto, __u16 src_port, __u16 dst_port) {
    if (iph->saddr == 0 || iph->daddr == 0) {
        return XDP_DROP;
    }

    if (iph->daddr == bpf_htonl(0xFFFFFFFF)) {
        return XDP_PASS;
    }

    if (iph->ttl == 0) {
        return XDP_DROP;
    }

    if (proto == IPPROTO_ICMP) {
        struct token_bucket_t *bucket, new_bucket = {0};
        __u32 key = iph->saddr;
        
        bucket = bpf_map_lookup_elem(&token_buckets, &key);
        if (!bucket) {
            new_bucket.last_update = bpf_ktime_get_ns();
            // Use config for ICMP limit
            struct attacks_config_t cfg;
            get_config(&cfg);
            new_bucket.tokens = cfg.icmp_flood_rate;
            bpf_map_update_elem(&token_buckets, &key, &new_bucket, BPF_ANY);
            return XDP_PASS;
        }

        struct attacks_config_t cfg;
        get_config(&cfg);
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - bucket->last_update;
        __u32 new_tokens = bucket->tokens + (elapsed * cfg.icmp_flood_rate / 1000000000);
        
        if (new_tokens > cfg.icmp_flood_rate) {
            new_tokens = cfg.icmp_flood_rate;
        }

        if (new_tokens >= 1) {
            new_tokens -= 1;
            bucket->tokens = new_tokens;
            bucket->last_update = now;
            return XDP_PASS;
        } else {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

static __always_inline int rate_limit(__u32 ip) {
    struct token_bucket_t *bucket, new_bucket = {0};
    
    bucket = bpf_map_lookup_elem(&token_buckets, &ip);
    if (!bucket) {
        new_bucket.last_update = bpf_ktime_get_ns();
        new_bucket.tokens = MAX_TOKENS;
        bpf_map_update_elem(&token_buckets, &ip, &new_bucket, BPF_ANY);
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - bucket->last_update;
    __u32 new_tokens = bucket->tokens + (elapsed * TOKENS_PER_SECOND / 1000000000);
    
    if (new_tokens > MAX_TOKENS) {
        new_tokens = MAX_TOKENS;
    }

    if (new_tokens >= 1) {
        new_tokens -= 1;
        bucket->tokens = new_tokens;
        bucket->last_update = now;
        return XDP_PASS;
    } else {
        return XDP_DROP;
    }
}

static __always_inline int check_geoip(__u32 src_ip) {
    struct geoip_key key = {
        .prefixlen = 32,
        .ip = src_ip
    };
    
    __u16 *country_code_ptr = bpf_map_lookup_elem(&geoip_map, &key);
    if (!country_code_ptr) {
        return XDP_PASS; // Unknown location, pass
    }
    
    __u16 country_code = *country_code_ptr;
    
    __u8 *action = bpf_map_lookup_elem(&blocked_countries, &country_code);
    if (action && *action == 1) {
        // bpf_printk("GeoIP Block: IP 0x%x (Country %u)", bpf_ntohl(src_ip), country_code);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Update global stats
    __u32 stats_key = 0;
    struct global_stats_t *stats = bpf_map_lookup_elem(&global_stats, &stats_key);
    if (stats) {
        stats->total_packets++;
        stats->total_bytes += (data_end - data);
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    int frag_action = handle_fragment(ip);
    if (frag_action != XDP_PASS)
        return frag_action;

    __u32 src_ip = ip->saddr;
    
    int geo_action = check_geoip(src_ip);
    if (geo_action != XDP_PASS)
        return geo_action;
        
    __u32 dst_ip = ip->daddr;
    __u16 src_port = 0, dst_port = 0;
    __u8 proto = ip->protocol;

    __u32 ip_header_length = ip->ihl * 4;
    __u32 l4_header_length = 0;
    __u32 payload_length = 0;
    __u8 tcp_flags = 0;

    int early_action = early_filter(ip, proto, src_port, dst_port);
    if (early_action != XDP_PASS)
        return early_action;

    // Protocol-specific rate limiting is more accurate than global limit
    // int rate_action = rate_limit(src_ip);  // REMOVED: Redundant global rate limit
    // if (rate_action != XDP_PASS)
    //     return rate_action;

    switch (proto) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (void *)ip + ip_header_length;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
            l4_header_length = tcp->doff * 4;
            tcp_flags = *((__u8 *)tcp + 13);
            int syn_flood_action = check_syn_flood(ip, tcp);
            if (syn_flood_action != XDP_PASS)
                return syn_flood_action;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = (void *)ip + ip_header_length;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
            l4_header_length = sizeof(struct udphdr);
            int dns_action = check_dns_amplification(ip, udp, udp->source == bpf_htons(DNS_PORT));
            if (dns_action != XDP_PASS)
                return dns_action;
            int udp_flood_action = check_udp_flood(ip, udp);
            if (udp_flood_action != XDP_PASS)
                return udp_flood_action;
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *icmp = (void *)ip + ip_header_length;
            if ((void *)(icmp + 1) > data_end)
                return XDP_PASS;
            src_port = icmp->type;
            dst_port = icmp->code;
            l4_header_length = sizeof(struct icmphdr);
            break;
        }
        default:
            return XDP_PASS;
    }

    payload_length = bpf_ntohs(ip->tot_len) - ip_header_length - l4_header_length;

    int action = apply_rule(src_ip, src_port, proto);
    if (action != XDP_PASS)
        return action;

    action = apply_rule(dst_ip, dst_port, proto);
    if (action != XDP_PASS)
        return action;

    __u32 index = 0;
    __u32 *host_ip_ptr = bpf_map_lookup_elem(&host_ip, &index);
    __u32 current_host_ip = host_ip_ptr ? *host_ip_ptr : 0;
    __u8 direction = (current_host_ip == dst_ip) ? 0 : 1;

    struct flow_key_t key = {0};
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.proto = proto;

    __u64 now = bpf_ktime_get_ns();
    struct traffic_info_t *info, new_info = {0};
    info = bpf_map_lookup_elem(&active_traffic, &key);
    if (!info) {
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
        bpf_map_update_elem(&active_traffic, &key, info, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";