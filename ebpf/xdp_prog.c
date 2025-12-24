#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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




struct attack_info {
    __u64 timestamp;
    __u32 src_ip;
    __u8 protocol;
    __u32 packets;
    __u64 bytes;


    
};

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

struct rule_t {
    __u16 port_start;
    __u16 port_end;
    __u8 proto;
    __u8 action;
};

struct token_bucket_t {
    __u64 last_update;
    __u32 tokens;
};

struct syn_flood_info {
    __u64 last_update;
    __u32 syn_count;
};

struct dns_info {
    __u64 last_update;
    __u32 packet_count;
    __u32 total_size;
};

struct frag_info {
    __u64 last_update;
    __u16 frag_count;
};

struct udp_flood_info {
    __u64 last_update;
    __u32 packet_count;
    __u32 byte_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct udp_flood_info);
} udp_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct frag_info);
} frag_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct dns_info);
} dns_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct syn_flood_info);
} syn_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct rule_t);
} rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
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
        //return -1;
    }

    struct attack_info new_attack = {
        .timestamp = bpf_ktime_get_ns(),
        .src_ip = src_ip,
        .protocol = protocol,
        .packets = packets,
        .bytes = bytes
    };

    // Update the attack info array
    int ret = bpf_map_update_elem(&attack_info_array, &count, &new_attack, BPF_ANY);
   

    // Increment and update the attack count
    count++;
     bpf_map_update_elem(&attack_count, &index, &count, BPF_ANY);
  
   // return 0;
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

static __always_inline int check_udp_flood(struct iphdr *iph, struct udphdr *udph) {
    __u32 src_ip = iph->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u32 pkt_size = bpf_ntohs(iph->tot_len);

    struct udp_flood_info *info, new_info = {0};
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
    
    if (time_diff < UDP_TRACK_TIMEOUT) {
        info->packet_count++;
        info->byte_count += pkt_size;

        __u64 pps = (info->packet_count * 1000000000ULL) / time_diff;

        if (pps > UDP_FLOOD_RATE && info->packet_count > UDP_FLOOD_BURST) {
            bpf_printk("UDP flood detected from IP 0x%x, PPS: %llu", bpf_ntohl(src_ip), pps);
           
            update_attack_info(src_ip, IPPROTO_UDP, 1, pkt_size);
            print_ip_and_pps(src_ip ,pps );
            return XDP_DROP;
        }
    } else {
        info->packet_count = 1;
        info->byte_count = pkt_size;
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
        info->packet_count++;
        info->total_size += packet_size;

        if (info->packet_count > MAX_DNS_PACKETS_PER_SEC) {
            bpf_printk("DNS rate limit exceeded for IP 0x%x", bpf_ntohl(src_ip));
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
                info->frag_count++;
            }
            info->last_update = now;

            if (info->frag_count > MAX_FRAGS_PER_IP) {
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
    struct rule_t *rule = bpf_map_lookup_elem(&rules, &ip);
    if (rule) {
        if ((rule->proto == 0 || rule->proto == proto) &&
            (rule->port_start == 0 || (port >= rule->port_start && port <= rule->port_end))) {
            bpf_printk("Match: ip=0x%x, port=%u, proto=%u", bpf_ntohl(ip), port, proto);
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
    }
    return XDP_PASS;
}

static __always_inline int check_syn_flood(struct iphdr *iph, struct tcphdr *tcph) {
    if (tcph->syn && !tcph->ack) {
        struct syn_flood_info *info, new_info = {0};
        __u32 src_ip = iph->saddr;
        
        info = bpf_map_lookup_elem(&syn_flood_map, &src_ip);
        if (!info) {
            new_info.last_update = bpf_ktime_get_ns();
            new_info.syn_count = 1;
            bpf_map_update_elem(&syn_flood_map, &src_ip, &new_info, BPF_ANY);
            return XDP_PASS;
        }

        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - info->last_update;
        
        if (elapsed < 1000000000) {
            info->syn_count++;
            if (info->syn_count > SYN_FLOOD_RATE) {
                bpf_printk("SYN flood detected from IP 0x%x", bpf_ntohl(src_ip));
                return XDP_DROP;
            }
        } else {
            info->last_update = now;
            info->syn_count = 1;
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
            new_bucket.tokens = ICMP_RATE_LIMIT;
            bpf_map_update_elem(&token_buckets, &key, &new_bucket, BPF_ANY);
            return XDP_PASS;
        }

        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - bucket->last_update;
        __u32 new_tokens = bucket->tokens + (elapsed * ICMP_RATE_LIMIT / 1000000000);
        
        if (new_tokens > ICMP_RATE_LIMIT) {
            new_tokens = ICMP_RATE_LIMIT;
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

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    int frag_action = handle_fragment(ip);
    if (frag_action != XDP_PASS)
        return frag_action;

    __u32 src_ip = ip->saddr;
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

    int rate_action = rate_limit(src_ip);
    if (rate_action != XDP_PASS)
        return rate_action;

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

    __u64 key = ((__u64)src_ip << 32) | dst_ip;
    key |= ((__u64)src_port << 16) | dst_port;
    key |= (__u64)proto;

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