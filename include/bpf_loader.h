#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <linux/if_link.h>
#include <stdint.h>
#include <stddef.h>
#include "api_handlers.h"
#include "common.h"

int load_bpf_program(const char *filename, const char *interface,
                     const struct cyrenus_ip *host_ips, int host_ip_count,
                     const struct attacks_config_t *initial_cfg,
                     struct map_fds *fds, char *xdp_mode_out, size_t xdp_mode_out_len);

void unload_bpf_program(const char *interface);

#endif // BPF_LOADER_H
