#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <linux/if_link.h>
#include <stdint.h>
// Function to load and attach the eBPF program


int load_bpf_program(const char *filename, const char *interface, uint32_t host_ip,
                     int *map_fd_rules, int *map_fd_traffic, int *map_fd_host_ip , int *map_fd_udp_flood_fd ,  int *map_fd_dns_track_fd , int *map_fd_syn_flood_fd , int  *map_fd_attack_info_array, int *map_fd_attack_count);
// Function to detach and unload the eBPF program
void unload_bpf_program(const char *interface);

 
#endif // BPF_LOADER_H