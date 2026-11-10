#include "../include/bpf_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static struct bpf_object *obj = NULL;

int load_bpf_program(const char *filename, const char *interface, uint32_t host_ip,
                     int *map_fd_rules, int *map_fd_traffic, int *map_fd_host_ip, int *map_fd_udp_flood_fd, int *map_fd_dns_track_fd, int *map_fd_syn_flood_fd, int *map_fd_attack_info_array, int *map_fd_attack_count, int *map_fd_geoip, int *map_fd_blocked_countries, int *map_fd_global_stats, int *map_fd_config) {
    struct bpf_program *prog;
    int prog_fd, ifindex;

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

    // Load eBPF program
    obj = bpf_object__open_file(filename, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object file '%s' failed: %s\n", filename, strerror(errno));
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file '%s' failed\n", filename);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    // Get file descriptor of eBPF program
    prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    prog_fd = prog ? bpf_program__fd(prog) : -1;
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: finding XDP program in object file '%s' failed\n", filename);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    // Attach eBPF program to network interface
    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: failed to get interface index for '%s'\n", interface);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    // Detach any existing XDP program from the interface
    struct bpf_xdp_query_opts qopts = { .sz = sizeof(qopts) };
    if (bpf_xdp_query(ifindex, 0, &qopts) == 0 && qopts.attach_mode != XDP_ATTACHED_NONE) {
        if (bpf_xdp_detach(ifindex, 0, NULL) < 0) {
            fprintf(stderr, "WARNING: failed to detach existing XDP program from '%s'\n", interface);
        }
    }

    // Try native XDP (DRV) first, then fall back to SKB generic mode
    int attach_err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE, NULL);
    if (attach_err < 0) {
        attach_err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE, NULL);
    }
    if (attach_err < 0) {
        fprintf(stderr, "ERROR: attaching XDP program to interface '%s' failed: %s\n", interface, strerror(-attach_err));
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    memset(&qopts, 0, sizeof(qopts));
    qopts.sz = sizeof(qopts);
    if (bpf_xdp_query(ifindex, 0, &qopts) == 0) {
        const char *mode_str = (qopts.attach_mode == XDP_ATTACHED_SKB) ? "SKB (generic)" :
                               (qopts.attach_mode == XDP_ATTACHED_DRV) ? "Native (DRV)" :
                               (qopts.attach_mode == XDP_ATTACHED_HW) ? "Hardware (HW)" : "Unknown";
        printf("XDP program attached successfully. Mode: %s (prog_id=%u)\n", mode_str, qopts.prog_id);
    } else {
        fprintf(stderr, "Failed to get XDP info after attachment\n");
    }

    // Get file descriptors of maps
    *map_fd_rules = bpf_object__find_map_fd_by_name(obj, "rules");
    if (*map_fd_rules < 0) {
        fprintf(stderr, "ERROR: finding 'rules' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_traffic = bpf_object__find_map_fd_by_name(obj, "active_traffic");
    if (*map_fd_traffic < 0) {
        fprintf(stderr, "ERROR: finding 'active_traffic' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_host_ip = bpf_object__find_map_fd_by_name(obj, "host_ip");
    if (*map_fd_host_ip < 0) {
        fprintf(stderr, "ERROR: finding 'host_ip' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_udp_flood_fd = bpf_object__find_map_fd_by_name(obj, "udp_flood_map");
    if (*map_fd_udp_flood_fd < 0) {
        fprintf(stderr, "ERROR: finding 'udp_flood_map' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_dns_track_fd = bpf_object__find_map_fd_by_name(obj, "dns_track_map");
    if (*map_fd_dns_track_fd < 0) {
        fprintf(stderr, "ERROR: finding 'dns_track_map' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_attack_info_array = bpf_object__find_map_fd_by_name(obj, "attack_info_array");
    if (*map_fd_attack_info_array < 0) {
        fprintf(stderr, "ERROR: finding 'attack_info_array' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_attack_count = bpf_object__find_map_fd_by_name(obj, "attack_count");
    if (*map_fd_attack_count < 0) {
        fprintf(stderr, "ERROR: finding 'attack_count' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_syn_flood_fd = bpf_object__find_map_fd_by_name(obj, "syn_flood_map");
    if (*map_fd_syn_flood_fd < 0) {
        fprintf(stderr, "ERROR: finding 'syn_flood_map' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_geoip = bpf_object__find_map_fd_by_name(obj, "geoip_map");
    if (*map_fd_geoip < 0) {
        fprintf(stderr, "ERROR: finding 'geoip_map' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_blocked_countries = bpf_object__find_map_fd_by_name(obj, "blocked_countries");
    if (*map_fd_blocked_countries < 0) {
        fprintf(stderr, "ERROR: finding 'blocked_countries' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_global_stats = bpf_object__find_map_fd_by_name(obj, "global_stats");
    if (*map_fd_global_stats < 0) {
        fprintf(stderr, "ERROR: finding 'global_stats' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    *map_fd_config = bpf_object__find_map_fd_by_name(obj, "config_map");
    if (*map_fd_config < 0) {
        fprintf(stderr, "ERROR: finding 'config_map' map in object file '%s' failed\n", filename);
        goto err_close;
    }

    uint32_t key = 0;  // We're using index 0 for the host IP
    if (bpf_map_update_elem(*map_fd_host_ip, &key, &host_ip, BPF_ANY) != 0) {
        fprintf(stderr, "Error updating host_ip map\n");
        goto err_close;
    }

    return 0;

err_close:
    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_object__close(obj);
    obj = NULL;
    return -1;
}

void unload_bpf_program(const char *interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index: %s\n", interface);
    } else {
        if (bpf_xdp_detach(ifindex, 0, NULL) < 0) {
            if (bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL) < 0 &&
                bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL) < 0) {
                fprintf(stderr, "Failed to detach XDP program from interface: %s\n", interface);
            } else {
                printf("Successfully detached XDP program from interface: %s\n", interface);
            }
        } else {
            printf("Successfully detached XDP program from interface: %s\n", interface);
        }
    }

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
}
