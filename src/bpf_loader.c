#include "../include/bpf_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
static struct bpf_object *obj;

 
int load_bpf_program(const char *filename, const char *interface, uint32_t host_ip,
                     int *map_fd_rules, int *map_fd_traffic, int *map_fd_host_ip , int *map_fd_udp_flood_fd ,  int *map_fd_dns_track_fd , int *map_fd_syn_flood_fd , int  *map_fd_attack_info_array, int *map_fd_attack_count, int *map_fd_geoip, int *map_fd_blocked_countries, int *map_fd_global_stats, int *map_fd_config) {
    struct bpf_object *obj;
    int prog_fd, ifindex;
   
 
    // Load eBPF program
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file '%s' failed\n", filename);
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file '%s' failed\n", filename);
        return -1;
    }

    // Get file descriptor of eBPF program
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_prog"));
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: finding XDP program in object file '%s' failed\n", filename);
        return -1;
    }

    // Attach eBPF program to network interface
    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: failed to get interface index for '%s'\n", interface);
        return -1;
    }

    // Detach any existing XDP program from the interface
    if (bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "WARNING: failed to detach existing XDP program from '%s'\n", interface);
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE) < 0) {
        fprintf(stderr, "ERROR: attaching XDP program to interface '%s' failed\n", interface);
        return -1;
    }

    struct xdp_link_info xdp_info;
    if (bpf_get_link_xdp_info(ifindex, &xdp_info, sizeof(xdp_info), 0) == 0) {
        printf("XDP program attached successfully. Mode: %s\n", 
            xdp_info.attach_mode == XDP_ATTACHED_SKB ? "SKB (generic)" : "Native");
    } else {
        fprintf(stderr, "Failed to get XDP info after attachment\n");
    }

    // Get file descriptors of maps
    *map_fd_rules = bpf_object__find_map_fd_by_name(obj, "rules");
    if (*map_fd_rules < 0) {
        fprintf(stderr, "ERROR: finding 'rules' map in object file '%s' failed\n", filename);
        return -1;
    }

    *map_fd_traffic = bpf_object__find_map_fd_by_name(obj, "active_traffic");
    if (*map_fd_traffic < 0) {
        fprintf(stderr, "ERROR: finding 'active_traffic' map in object file '%s' failed\n", filename);
        return -1;
    }

    *map_fd_host_ip = bpf_object__find_map_fd_by_name(obj, "host_ip");
    if (*map_fd_host_ip < 0) {
        fprintf(stderr, "ERROR: finding 'host_ip' map in object file '%s' failed\n", filename);
        return -1;
    }

   

 *map_fd_udp_flood_fd = bpf_object__find_map_fd_by_name(obj, "udp_flood_map");
    if (*map_fd_udp_flood_fd < 0) {
        fprintf(stderr, "ERROR: finding 'udp_flood' map in object file '%s' failed\n", filename);
        return -1;
    }

 *map_fd_dns_track_fd = bpf_object__find_map_fd_by_name(obj, "dns_track_map");
    if (*map_fd_dns_track_fd < 0) {
        fprintf(stderr, "ERROR: finding 'dns_track_map' map in object file '%s' failed\n", filename);
        return -1;
    }


*map_fd_attack_info_array = bpf_object__find_map_fd_by_name(obj, "attack_info_array");
    if (*map_fd_attack_info_array < 0) {
        fprintf(stderr, "ERROR: finding 'attack_info_array' map in object file '%s' failed\n", filename);
        return -1;
    }


*map_fd_attack_count = bpf_object__find_map_fd_by_name(obj, "attack_count");
    if (*map_fd_attack_count < 0) {
        fprintf(stderr, "ERROR: finding 'attack_count' map in object file '%s' failed\n", filename);
        return -1;
    }
 

    *map_fd_syn_flood_fd = bpf_object__find_map_fd_by_name(obj, "syn_flood_map");
    if (*map_fd_syn_flood_fd < 0) {
        fprintf(stderr, "ERROR: finding 'syn_flood_map' map in object file '%s' failed\n", filename);
        return -1;
    }

    *map_fd_geoip = bpf_object__find_map_fd_by_name(obj, "geoip_map");
    if (*map_fd_geoip < 0) {
        fprintf(stderr, "ERROR: finding 'geoip_map' map in object file '%s' failed\n", filename);
        return -1;
    }

    *map_fd_blocked_countries = bpf_object__find_map_fd_by_name(obj, "blocked_countries");
    if (*map_fd_blocked_countries < 0) {
        fprintf(stderr, "ERROR: finding 'blocked_countries' map in object file '%s' failed\n", filename);
        return -1;
    }

    *map_fd_global_stats = bpf_object__find_map_fd_by_name(obj, "global_stats");
    if (*map_fd_global_stats < 0) {
        fprintf(stderr, "ERROR: finding 'global_stats' map in object file '%s' failed\n", filename);
        return -1;
    }

    *map_fd_config = bpf_object__find_map_fd_by_name(obj, "config_map");
    if (*map_fd_config < 0) {
        fprintf(stderr, "ERROR: finding 'config_map' map in object file '%s' failed\n", filename);
        return -1;
    }

 uint32_t key = 0;  // We're using index 0 for the host IP
    if (bpf_map_update_elem(*map_fd_host_ip, &key, &host_ip, BPF_ANY) != 0) {
        fprintf(stderr, "Error updating host_ip map\n");
        return -1;
    }
 
    return 0;
}


void unload_bpf_program(const char *interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index: %s\n", interface);
        return;
    }

    if (bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Failed to detach XDP program from interface: %s\n", interface);
    } else {
        printf("Successfully detached XDP program from interface: %s\n", interface);
    }

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
}
