#ifndef RUNTIME_CONFIG_H
#define RUNTIME_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include "config_handler.h"
#include "common.h"

#define MAX_PATH_LEN 512
#define MAX_URL_LEN 256
#define MAX_STRING_LEN 128

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct runtime_config {
    // Configuration source
    char config_file_path[MAX_PATH_LEN];

    // Network settings
    char interface[IFNAMSIZ];
    uint16_t http_port;
    char xdp_mode[32];
    time_t start_time;

    // Backend/API
    char backend_url[MAX_URL_LEN];
    char api_key[64];
    char app_secret[64];

    // Authentication
    char username[MAX_STRING_LEN];
    char password[MAX_STRING_LEN];

    // Paths
    char database_path[MAX_PATH_LEN];
    char geoip_db_path[MAX_PATH_LEN];
    char master_key_path[MAX_PATH_LEN];

    // Feature flags
    bool dry_run;
    bool verbose;
    bool debug;
    bool no_geoip;
    bool no_notifications;
    bool daemon_mode;

    // Logging and Environment
    char log_file[MAX_PATH_LEN];
    int log_level;
    char environment[32];

    // Attack Detection & Mitigation Thresholds
    uint32_t syn_flood_rate;
    uint32_t udp_flood_rate;
    uint32_t icmp_flood_rate;
    uint32_t dns_amp_rate;
    uint32_t max_frags;
    uint32_t auto_block_enabled;
    uint32_t auto_block_duration_sec;
    uint32_t global_syn_rate;
    uint32_t global_udp_rate;
    uint32_t max_dns_response_size;
};

void runtime_config_init(struct runtime_config *rc);
int runtime_config_parse_args(int argc, char **argv, struct runtime_config *rc);
int runtime_config_load_file(struct runtime_config *rc);
void runtime_config_load_env(struct runtime_config *rc);
int runtime_config_validate(const struct runtime_config *rc);
void runtime_config_print(const struct runtime_config *rc);
void runtime_config_to_bpf_cfg(const struct runtime_config *rc, struct attacks_config_t *cfg);

void runtime_config_print_usage(const char *program_name);
void runtime_config_print_version(void);

#define ENV_CYRENUS_INTERFACE       "CYRENUS_INTERFACE"
#define ENV_CYRENUS_HTTP_PORT       "CYRENUS_HTTP_PORT"
#define ENV_CYRENUS_CONFIG          "CYRENUS_CONFIG"
#define ENV_CYRENUS_DB_PATH         "CYRENUS_DB_PATH"
#define ENV_CYRENUS_GEOIP_DB        "CYRENUS_GEOIP_DB"
#define ENV_CYRENUS_MASTER_KEY      "CYRENUS_MASTER_KEY"
#define ENV_CYRENUS_ENV             "CYRENUS_ENV"
#define ENV_CYRENUS_LOG_LEVEL       "CYRENUS_LOG_LEVEL"
#define ENV_CYRENUS_LOG_FILE        "CYRENUS_LOG_FILE"

#endif // RUNTIME_CONFIG_H
