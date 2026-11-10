#ifndef API_HANDLERS_H
#define API_HANDLERS_H

#include <microhttpd.h>
#include <json-c/json.h>
#include "database.h"
#include "runtime_config.h"

struct map_fds {
    int rules_fd;
    int traffic_fd;
    int udp_flood_fd;
    int dns_track_fd;
    int syn_flood_fd;
    int attack_info_array_fd;
    int attack_count_fd;
    int active_attacks_fd;
    int auto_block_fd;
    int ip_whitelist_fd;
    int ip_blacklist_fd;
    int geoip_map_fd;
    int geoip6_map_fd;
    int blocked_countries_fd;
    int global_stats_fd;
    int config_map_fd;
    int host_ips_fd;
};

struct api_context {
    struct database *db;
    struct runtime_config *config;
    struct map_fds *fds;
};

// Shared HTTP JSON, CORS, and security header helpers
void api_helpers_set_config(const struct runtime_config *cfg);
void api_apply_response_headers(struct MHD_Connection *connection, struct MHD_Response *response);
enum MHD_Result api_send_json(struct MHD_Connection *connection, int status_code, const char *json_str);
enum MHD_Result api_send_error(struct MHD_Connection *connection, int status_code, const char *message);
enum MHD_Result api_send_rate_limited(struct MHD_Connection *connection, int retry_after_sec, const char *message);

// --- Authentication ---
enum MHD_Result api_auth_login(struct MHD_Connection *connection,
                               struct api_context *ctx,
                               const char *upload_data, size_t size);
enum MHD_Result api_auth_logout(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *token);
enum MHD_Result api_auth_verify(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *token);

// --- System ---
enum MHD_Result api_system_health(struct MHD_Connection *connection,
                                  struct api_context *ctx);
enum MHD_Result api_system_stats(struct MHD_Connection *connection,
                                 struct api_context *ctx);
enum MHD_Result api_system_get_settings(struct MHD_Connection *connection,
                                        struct api_context *ctx);
enum MHD_Result api_system_update_settings(struct MHD_Connection *connection,
                                           struct api_context *ctx,
                                           const char *upload_data, size_t size);

// --- Attacks & Active Blocks ---
enum MHD_Result api_attacks_list(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *year, const char *month);
enum MHD_Result api_attacks_get(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                int id);
enum MHD_Result api_attacks_resolve(struct MHD_Connection *connection,
                                    struct api_context *ctx,
                                    const char *id_str);
enum MHD_Result api_attacks_clear(struct MHD_Connection *connection,
                                  struct api_context *ctx);
enum MHD_Result api_blocks_list(struct MHD_Connection *connection,
                                struct api_context *ctx);
enum MHD_Result api_blocks_delete(struct MHD_Connection *connection,
                                  struct api_context *ctx,
                                  const char *ip_str);

// --- Traffic ---
enum MHD_Result api_traffic_stats(struct MHD_Connection *connection,
                                  struct api_context *ctx);

// --- Rules ---
enum MHD_Result api_rules_list(struct MHD_Connection *connection,
                               struct api_context *ctx);
enum MHD_Result api_rules_create(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *upload_data, size_t size);
enum MHD_Result api_rules_delete(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *id_str);

// --- IP Lists (Whitelist / Blacklist) ---
enum MHD_Result api_iplists_get(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *list_type);
enum MHD_Result api_iplists_add(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *upload_data, size_t size);
enum MHD_Result api_iplists_delete(struct MHD_Connection *connection,
                                   struct api_context *ctx,
                                   int id);

// --- GeoIP ---
enum MHD_Result api_geoip_lookup(struct MHD_Connection *connection,
                                 struct api_context *ctx,
                                 const char *ip_str);
enum MHD_Result api_geoip_list_rules(struct MHD_Connection *connection,
                                     struct api_context *ctx);
enum MHD_Result api_geoip_add_rule(struct MHD_Connection *connection,
                                   struct api_context *ctx,
                                   const char *upload_data, size_t size);
enum MHD_Result api_geoip_delete_rule(struct MHD_Connection *connection,
                                      struct api_context *ctx,
                                      const char *id_str);

// --- API Keys ---
void hash_api_key(const char *key, char *hash_out);
enum MHD_Result api_keys_list(struct MHD_Connection *connection, struct api_context *ctx);
enum MHD_Result api_keys_create(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size);
enum MHD_Result api_keys_delete(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size);

// --- Security / Tetragon ---
struct MHD_Response *create_response(int status_code, const char *content, const char *content_type);
struct MHD_Response *create_json_response(int status_code, const char *json);
int api_security_last_status(void);

struct MHD_Response *api_security_events_list(struct MHD_Connection *connection, const char *method, const char *url);
struct MHD_Response *api_security_stats(struct MHD_Connection *connection, const char *method, const char *url);
struct MHD_Response *api_security_policies_list(struct MHD_Connection *connection, const char *method, const char *url);
struct MHD_Response *api_security_policy_get(struct MHD_Connection *connection, const char *method, const char *url, const char *policy_name);
struct MHD_Response *api_security_policy_save(struct MHD_Connection *connection, const char *method, const char *policy_name, const char *upload_data, size_t upload_data_size);
struct MHD_Response *api_security_policy_deploy(struct MHD_Connection *connection, const char *method, const char *policy_name);
struct MHD_Response *api_security_policy_delete(struct MHD_Connection *connection, const char *method, const char *policy_name);
struct MHD_Response *api_security_logs(struct MHD_Connection *connection, const char *method, const char *url);
struct MHD_Response *api_security_config_get(struct MHD_Connection *connection, const char *method, const char *url);
struct MHD_Response *api_security_config_save(struct MHD_Connection *connection, const char *method, const char *upload_data, size_t upload_data_size);
struct MHD_Response *api_security_correlations_list(struct MHD_Connection *connection, const char *method, const char *url);

#endif // API_HANDLERS_H
