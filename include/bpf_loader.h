#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <linux/if_link.h>
#include <stdint.h>
#include "api_handlers.h"
#include "common.h"

int load_bpf_program(const char *filename, const char *interface, uint32_t host_ip,
                     const struct attacks_config_t *initial_cfg,
                     struct map_fds *fds, char *xdp_mode_out, size_t xdp_mode_out_len);

void unload_bpf_program(const char *interface);

#endif // BPF_LOADER_H
