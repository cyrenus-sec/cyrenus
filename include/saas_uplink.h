#ifndef SAAS_UPLINK_H
#define SAAS_UPLINK_H

#include "runtime_config.h"
#include "database.h"
#include "api_handlers.h" // For map_fds

// Structure for SaaS context
struct saas_context {
    struct runtime_config *config;
    struct database *db;
    struct map_fds *fds; // To apply global blocks
    int running;
};

// Initialize SaaS Uplink
int saas_uplink_init(struct saas_context *ctx, struct runtime_config *cfg, struct database *db, struct map_fds *fds);

// Thread function for background polling
void *saas_uplink_thread(void *arg);

// Cleanup
void saas_uplink_cleanup(struct saas_context *ctx);

#endif // SAAS_UPLINK_H
