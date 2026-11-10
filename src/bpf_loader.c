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

static void init_invalid_fds(struct map_fds *fds) {
    fds->rules_fd = -1;
    fds->traffic_fd = -1;
    fds->udp_flood_fd = -1;
    fds->dns_track_fd = -1;
    fds->syn_flood_fd = -1;
    fds->attack_info_array_fd = -1;
    fds->attack_count_fd = -1;
    fds->active_attacks_fd = -1;
    fds->auto_block_fd = -1;
    fds->ip_whitelist_fd = -1;
    fds->ip_blacklist_fd = -1;
    fds->geoip_map_fd = -1;
    fds->geoip6_map_fd = -1;
    fds->blocked_countries_fd = -1;
    fds->global_stats_fd = -1;
    fds->config_map_fd = -1;
    fds->host_ips_fd = -1;
}

static int find_map_fd(struct bpf_object *bpf_obj, const char *name, const char *filename) {
    int fd = bpf_object__find_map_fd_by_name(bpf_obj, name);
    if (fd < 0) {
        fprintf(stderr, "ERROR: finding '%s' map in object file '%s' failed\n", name, filename);
    }
    return fd;
}

int load_bpf_program(const char *filename, const char *interface,
                     const struct cyrenus_ip *host_ips, int host_ip_count,
                     const struct attacks_config_t *initial_cfg,
                     struct map_fds *fds, char *xdp_mode_out, size_t xdp_mode_out_len) {
    struct bpf_program *prog;
    int prog_fd, ifindex;

    if (!fds) return -1;
    init_invalid_fds(fds);

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

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

    prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    prog_fd = prog ? bpf_program__fd(prog) : -1;
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: finding XDP program in object file '%s' failed\n", filename);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: failed to get interface index for '%s'\n", interface);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    struct bpf_xdp_query_opts qopts = { .sz = sizeof(qopts) };
    if (bpf_xdp_query(ifindex, 0, &qopts) == 0 && qopts.attach_mode != XDP_ATTACHED_NONE) {
        if (bpf_xdp_detach(ifindex, 0, NULL) < 0) {
            fprintf(stderr, "WARNING: failed to detach existing XDP program from '%s'\n", interface);
        }
    }

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
        if (xdp_mode_out && xdp_mode_out_len > 0) {
            snprintf(xdp_mode_out, xdp_mode_out_len, "%s", mode_str);
        }
    } else {
        fprintf(stderr, "Failed to get XDP info after attachment\n");
    }

    fds->rules_fd = find_map_fd(obj, "rules", filename);
    fds->traffic_fd = find_map_fd(obj, "active_traffic", filename);
    fds->host_ips_fd = find_map_fd(obj, "host_ips", filename);
    fds->udp_flood_fd = find_map_fd(obj, "udp_flood_map", filename);
    fds->dns_track_fd = find_map_fd(obj, "dns_track_map", filename);
    fds->syn_flood_fd = find_map_fd(obj, "syn_flood_map", filename);
    fds->attack_info_array_fd = find_map_fd(obj, "attack_info_array", filename);
    fds->attack_count_fd = find_map_fd(obj, "attack_count", filename);
    fds->active_attacks_fd = find_map_fd(obj, "active_attacks_map", filename);
    fds->auto_block_fd = find_map_fd(obj, "auto_block_map", filename);
    fds->ip_whitelist_fd = find_map_fd(obj, "ip_whitelist", filename);
    fds->ip_blacklist_fd = find_map_fd(obj, "ip_blacklist", filename);
    fds->geoip_map_fd = find_map_fd(obj, "geoip_map", filename);
    fds->geoip6_map_fd = find_map_fd(obj, "geoip6_map", filename);
    fds->blocked_countries_fd = find_map_fd(obj, "blocked_countries", filename);
    fds->global_stats_fd = find_map_fd(obj, "global_stats", filename);
    fds->config_map_fd = find_map_fd(obj, "config_map", filename);

    if (fds->rules_fd < 0 || fds->traffic_fd < 0 || fds->host_ips_fd < 0 ||
        fds->udp_flood_fd < 0 || fds->dns_track_fd < 0 || fds->syn_flood_fd < 0 ||
        fds->attack_info_array_fd < 0 || fds->attack_count_fd < 0 ||
        fds->active_attacks_fd < 0 || fds->auto_block_fd < 0 ||
        fds->ip_whitelist_fd < 0 || fds->ip_blacklist_fd < 0 ||
        fds->geoip_map_fd < 0 || fds->geoip6_map_fd < 0 ||
        fds->blocked_countries_fd < 0 || fds->global_stats_fd < 0 ||
        fds->config_map_fd < 0) {
        goto err_close;
    }

    if (host_ips && host_ip_count > 0) {
        uint8_t val = 1;
        for (int i = 0; i < host_ip_count; i++) {
            if (bpf_map_update_elem(fds->host_ips_fd, &host_ips[i], &val, BPF_ANY) != 0) {
                fprintf(stderr, "Warning: failed inserting host IP[%d] into host_ips map: %s\n",
                        i, strerror(errno));
            }
        }
        printf("Registered %d interface host IP(s) in host_ips map\n", host_ip_count);
    }

    // Immediately populate config_map so XDP never reads zeroed thresholds
    if (initial_cfg) {
        uint32_t key = 0;
        if (bpf_map_update_elem(fds->config_map_fd, &key, initial_cfg, BPF_ANY) != 0) {
            fprintf(stderr, "Error populating config_map: %s\n", strerror(errno));
            goto err_close;
        }
        printf("BPF config_map initialized: SYN=%u SYNACK=%u RST=%u ACK=%u UDP=%u ICMP=%u DNS=%u FRAGS=%u AutoBlock=%u(%us)\n",
               initial_cfg->syn_flood_rate, initial_cfg->synack_flood_rate,
               initial_cfg->rst_flood_rate, initial_cfg->ack_flood_rate,
               initial_cfg->udp_flood_rate, initial_cfg->icmp_flood_rate,
               initial_cfg->dns_amp_rate, initial_cfg->max_frags,
               initial_cfg->auto_block_enabled, initial_cfg->auto_block_duration_sec);
    }

    return 0;

err_close:
    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_object__close(obj);
    obj = NULL;
    init_invalid_fds(fds);
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
