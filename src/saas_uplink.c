#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/saas_uplink.h"
#include "../include/attack_info.h"
#include "../include/common.h"

int saas_uplink_init(struct saas_context *ctx, struct runtime_config *cfg, struct database *db, struct map_fds *fds) {
    ctx->config = cfg;
    ctx->db = db;
    ctx->fds = fds;
    ctx->running = 0;
    return 0;
}

void saas_uplink_cleanup(struct saas_context *ctx) {
    ctx->running = 0;
}

static void apply_global_block(struct saas_context *ctx, const char *ip_str) __attribute__((unused));
static void apply_global_block(struct saas_context *ctx, const char *ip_str) {
    if (!ctx->fds || ctx->fds->rules_fd < 0) return;

    struct rule_key_t key = {0};
    if (cyrenus_str_to_ip(ip_str, &key.ip, NULL) != 0) {
        printf("SaaS: Invalid IP format %s\n", ip_str);
        return;
    }

    key.port = 0;
    key.proto = 0;

    struct rule_t rule = {
        .action = ACTION_DROP
    };

    bpf_map_update_elem(ctx->fds->rules_fd, &key, &rule, BPF_ANY);
    printf("SaaS: Applied GLOBAL BLOCK for %s\n", ip_str);
}

void *saas_uplink_thread(void *arg) {
    struct saas_context *ctx = (struct saas_context *)arg;
    ctx->running = 1;

    printf("SaaS Uplink: Connecting to %s...\n", ctx->config->backend_url[0] ? ctx->config->backend_url : "Cloud (Simulated)");

    while (ctx->running) {
        // 1. Send Heartbeat / Stats
        // curl_post(ctx->config->backend_url, json_stats) ...

        // 2. Poll for Commands
        // For Proof of Concept, we just simulate receiving a block command occasionally
        // or check a local "command" file if we wanted.
        
        // printf("SaaS: Heartbeat sent. Status IDLE.\n");

        // Simulation: Apply block to 1.2.3.4 once
        static int simulated = 0;
        if (!simulated && ctx->running) {
             // apply_global_block(ctx, "1.2.3.4");
             simulated = 1;
        }

        sleep(10); // Poll every 10 seconds
    }

    return NULL;
}
