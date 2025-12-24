 #include "../include/attack_info.h" // Include the new attack_info header

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

// These should be initialized in your main application
extern int map_fd_udp_flood;
extern int map_fd_dns_track;
extern int map_fd_syn_flood;

extern int map_fd_attack_info_array;
extern int map_fd_attack_count;

const char* get_proto_name(uint8_t proto)  {
    switch(proto) {
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


int get_attack_info(struct attack_info **attacks, int map_fd_attack_info_array, int map_fd_attack_count) {
    fprintf(stderr, "Entering get_attack_info\n");
    
    *attacks = calloc(MAX_ATTACKS, sizeof(struct attack_info));
    if (!*attacks) {
        fprintf(stderr, "Failed to allocate memory for attack info\n");
        return 0;
    }

    uint32_t attack_count = 0;
    /*
    
    uint32_t count_key = 0;
      if (bpf_map_lookup_elem(map_fd_attack_count, &count_key, &attack_count) != 0) {
        fprintf(stderr, "Failed to lookup attack count\n");
        free(*attacks);
        *attacks = NULL;
        return 0;
    }

    fprintf(stderr, "Retrieved attack count: %u\n", attack_count);

    if (attack_count > MAX_ATTACKS) {
        attack_count = MAX_ATTACKS;
    }
    */
  

      uint32_t key = {0}, next_key = {0};
   while (bpf_map_get_next_key(map_fd_attack_info_array, &key, &next_key) == 0) 
    {
        struct attack_info ebpf_attack;
         if (bpf_map_lookup_elem(map_fd_attack_info_array, &next_key, &ebpf_attack) == 0) {
             

                 struct attack_info *attack = &(*attacks)[next_key];
                attack->timestamp = ebpf_attack.timestamp;
                attack->src_ip = ebpf_attack.src_ip;
                attack->protocol = ebpf_attack.protocol;
                attack->packets = ebpf_attack.packets;
                attack->bytes = ebpf_attack.bytes;

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(attack->src_ip), ip_str, INET_ADDRSTRLEN);
                fprintf(stderr, "Retrieved attack from IP: %s\n", ip_str);
                attack_count++;
            }

           
            key = next_key;
        /* code */
    }

   /* for (uint32_t i = 0; i < attack_count; i++) {
        struct attack_info ebpf_attack;
        if (bpf_map_lookup_elem(map_fd_attack_info_array, &i, &ebpf_attack) != 0) {
            fprintf(stderr, "Failed to lookup attack info for index %u\n", i);
            continue;
        }

        struct attack_info *attack = &(*attacks)[i];
        attack->timestamp = ebpf_attack.timestamp;
        attack->src_ip = ebpf_attack.src_ip;
        attack->protocol = ebpf_attack.protocol;
        attack->packets = ebpf_attack.packets;
        attack->bytes = ebpf_attack.bytes;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(attack->src_ip), ip_str, INET_ADDRSTRLEN);
        fprintf(stderr, "Retrieved attack from IP: %s\n", ip_str);
    } */

    fprintf(stderr, "Exiting get_attack_info, found %u attacks\n", attack_count);
    return attack_count;
}
/*
int get_attack_info(struct attack_info **attacks) {
    fprintf(stderr, "Entering get_attack_info\n");
    
    *attacks = calloc(MAX_ATTACKS, sizeof(struct attack_info));
    if (!*attacks) {
        fprintf(stderr, "Failed to allocate memory for attack info\n");
        return 0;
    }

    uint32_t count_key = 0;
    uint32_t attack_count = 0;
    if (bpf_map_lookup_elem(map_fd_attack_count, &count_key, &attack_count) != 0) {
        fprintf(stderr, "Failed to lookup attack count\n");
        free(*attacks);
        *attacks = NULL;
        return 0;
    }

    fprintf(stderr, "Retrieved attack count: %u\n", attack_count);

    if (attack_count > MAX_ATTACKS) {
        attack_count = MAX_ATTACKS;
    }

    for (uint32_t i = 0; i < attack_count; i++) {
        struct attack_info ebpf_attack;
        if (bpf_map_lookup_elem(map_fd_attack_info_array, &i, &ebpf_attack) != 0) {
            fprintf(stderr, "Failed to lookup attack info for index %u\n", i);
            continue;
        }

        struct attack_info *attack = &(*attacks)[i];
        attack->timestamp = ebpf_attack.timestamp;
        attack->src_ip = ebpf_attack.src_ip;
        attack->protocol = ebpf_attack.protocol;
        attack->packets = ebpf_attack.packets;
        attack->bytes = ebpf_attack.bytes;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(attack->src_ip), ip_str, INET_ADDRSTRLEN);
        fprintf(stderr, "Retrieved attack from IP: %s\n", ip_str);
    }

    fprintf(stderr, "Exiting get_attack_info, found %u attacks\n", attack_count);
    return attack_count;
}
 
int get_attack_info(struct attack_info **attacks) {
    fprintf(stderr, "Entering get_attack_info\n");
    
    *attacks = calloc(MAX_ATTACKS, sizeof(struct attack_info));
    if (!*attacks) {
        fprintf(stderr, "Failed to allocate memory for attack info\n");
        return 0;
    }

    int attack_count = 0;
 
    uint32_t key = 0, next_key = 0;

    // Retrieve UDP flood attacks
    struct udp_flood_info udp_info;
    fprintf(stderr, "Checking UDP flood attacks\n");
    while (bpf_map_get_next_key(map_fd_udp_flood, &key, &next_key) == 0  ) {
        fprintf(stderr, "Checking key: %u\n", next_key);
        if (bpf_map_lookup_elem(map_fd_udp_flood, &next_key, &udp_info) == 0) {
            struct attack_info *attack = &(*attacks)[attack_count];
            attack->timestamp = udp_info.last_update;
            attack->src_ip = next_key;  // Keep in network byte order
            attack->protocol = IPPROTO_UDP;
            snprintf(attack->attack_type, sizeof(attack->attack_type), "UDP Flood");
            attack->packets = udp_info.packet_count;
            attack->bytes = udp_info.byte_count;
            
            // Convert and print IP address
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str))) {
                fprintf(stderr, "Found UDP flood attack from IP: %s\n", ip_str);
            } else {
                fprintf(stderr, "Failed to convert IP address\n");
            }
            
            attack_count++;
        } else {
            fprintf(stderr, "Failed to lookup element for key %u\n", next_key);
            
        }
        key = next_key;
    }

 

    // Retrieve DNS amplification attacks
    struct dns_info dns_info;
    key = 0;
    while (bpf_map_get_next_key(map_fd_dns_track, &key, &next_key) == 0 && attack_count < MAX_ATTACKS) {
        if (bpf_map_lookup_elem(map_fd_dns_track, &next_key, &dns_info) == 0) {
            if (dns_info.packet_count > MAX_DNS_PACKETS_PER_SEC) {
                struct attack_info *attack = &(*attacks)[attack_count++];
                attack->timestamp = dns_info.last_update;
                attack->src_ip = next_key;
                attack->protocol = IPPROTO_UDP;
                snprintf(attack->attack_type, sizeof(attack->attack_type), "DNS Amplification");
                attack->packets = dns_info.packet_count;
                attack->bytes = dns_info.total_size;
            }
        }
        key = next_key;
    }

    // Retrieve SYN flood attacks
    struct syn_flood_info syn_info;
    key = 0;
    while (bpf_map_get_next_key(map_fd_syn_flood, &key, &next_key) == 0 && attack_count < MAX_ATTACKS) {
        if (bpf_map_lookup_elem(map_fd_syn_flood, &next_key, &syn_info) == 0) {
            if (syn_info.syn_count > SYN_FLOOD_RATE) {
                struct attack_info *attack = &(*attacks)[attack_count++];
                attack->timestamp = syn_info.last_update;
                attack->src_ip = next_key;
                attack->protocol = IPPROTO_TCP;
                snprintf(attack->attack_type, sizeof(attack->attack_type), "SYN Flood");
                attack->packets = syn_info.syn_count;
            }
        }
        key = next_key;
    }
    
    return attack_count;
}
*/

void print_attack_info(struct attack_info *attack) {
    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(attack->src_ip), src_ip_str, INET_ADDRSTRLEN);
    
    printf("Attack Type: %s\n", attack->attack_type);
    printf("Timestamp: %lu\n", attack->timestamp);
    printf("Source IP: %s\n", src_ip_str);
    printf("Protocol: %s\n", get_proto_name(attack->protocol));
    printf("Packets: %u\n", attack->packets);
    printf("Bytes: %lu\n", attack->bytes);
    printf("------------------------------\n");
}