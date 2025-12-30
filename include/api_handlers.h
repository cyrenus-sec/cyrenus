#ifndef API_HANDLERS_H
#define API_HANDLERS_H

#include <microhttpd.h>
#include <json-c/json.h>
#include "database.h"
#include "runtime_config.h"

// Context for API handlers
struct map_fds {
    int rules_fd;
    int traffic_fd;
    int udp_flood_fd;
    int dns_track_fd;
    int syn_flood_fd;
    int attack_info_array_fd;
    int attack_count_fd;
    int geoip_map_fd;
    int blocked_countries_fd;
    int global_stats_fd;
    int config_map_fd;
};

struct api_context {
    struct database *db;
    struct runtime_config *config;
    struct map_fds *fds; // Typed pointer instead of void*
};

// --- Authentication ---
// POST /api/v1/auth/login
enum MHD_Result api_auth_login(struct MHD_Connection *connection, 
                               struct api_context *ctx,
                               const char *upload_data, size_t size);

// POST /api/v1/auth/logout
enum MHD_Result api_auth_logout(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *token);

// GET /api/v1/auth/verify
enum MHD_Result api_auth_verify(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *token);

// GET /api/v1/system/settings
enum MHD_Result api_system_get_settings(struct MHD_Connection *connection, 
                                        struct api_context *ctx);

// GET /api/v1/system/health
enum MHD_Result api_system_health(struct MHD_Connection *connection, 
                                  struct api_context *ctx);

// POST /api/v1/system/settings
enum MHD_Result api_system_update_settings(struct MHD_Connection *connection, 
                                           struct api_context *ctx,
                                           const char *upload_data, size_t size);

// --- Attacks ---
// GET /api/v1/attacks
enum MHD_Result api_attacks_list(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *year, const char *month); // Query params

// GET /api/v1/attacks/:id
enum MHD_Result api_attacks_get(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                int id);

// --- Traffic ---
// GET /api/v1/traffic/stats
enum MHD_Result api_traffic_stats(struct MHD_Connection *connection, 
                                  struct api_context *ctx);

// --- Rules ---
// GET /api/v1/rules
enum MHD_Result api_rules_list(struct MHD_Connection *connection, 
                               struct api_context *ctx);

// POST /api/v1/rules
enum MHD_Result api_rules_create(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *upload_data, size_t size);

// DELETE /api/v1/rules/:id
enum MHD_Result api_rules_delete(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *id_str);

// --- IP Lists (Whitelist/Blacklist) ---
// GET /api/v1/iplists/:type
enum MHD_Result api_iplists_get(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *list_type);

// POST /api/v1/iplists
enum MHD_Result api_iplists_add(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *upload_data, size_t size);

// DELETE /api/v1/iplists/:id
enum MHD_Result api_iplists_delete(struct MHD_Connection *connection, 
                                   struct api_context *ctx,
                                   int id);

// --- GeoIP ---
// GET /api/v1/geoip/:ip
enum MHD_Result api_geoip_lookup(struct MHD_Connection *connection, 
                                 struct api_context *ctx,
                                 const char *ip_str);

// GET /api/v1/geoip/rules
enum MHD_Result api_geoip_list_rules(struct MHD_Connection *connection, 
                                     struct api_context *ctx);

// POST /api/v1/geoip/rules
enum MHD_Result api_geoip_add_rule(struct MHD_Connection *connection, 
                                   struct api_context *ctx,
                                   const char *upload_data, size_t size);

// DELETE /api/v1/geoip/rules/:id
enum MHD_Result api_geoip_delete_rule(struct MHD_Connection *connection, 
                                      struct api_context *ctx,
                                      const char *id_str);

// API Key Handlers
void hash_api_key(const char *key, char *hash_out);

enum MHD_Result api_keys_list(struct MHD_Connection *connection, struct api_context *ctx);
enum MHD_Result api_keys_create(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size);
enum MHD_Result api_keys_delete(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size);

// --- Security / Tetragon ---
// Helper functions for creating responses
struct MHD_Response *create_response(int status_code, const char *content, const char *content_type);
struct MHD_Response *create_json_response(int status_code, const char *json);

// GET /api/v1/security/events
struct MHD_Response *api_security_events_list(struct MHD_Connection *connection, const char *method, const char *url);

// GET /api/v1/security/stats
struct MHD_Response *api_security_stats(struct MHD_Connection *connection, const char *method, const char *url);

// GET /api/v1/security/policies
struct MHD_Response *api_security_policies_list(struct MHD_Connection *connection, const char *method, const char *url);

// GET /api/v1/security/policy/:name
struct MHD_Response *api_security_policy_get(struct MHD_Connection *connection, const char *method, const char *url, const char *policy_name);

// POST /api/v1/security/policy/:name
struct MHD_Response *api_security_policy_save(struct MHD_Connection *connection, const char *method, const char *policy_name, const char *upload_data, size_t upload_data_size);

// POST /api/v1/security/policy/:name/deploy
struct MHD_Response *api_security_policy_deploy(struct MHD_Connection *connection, const char *method, const char *policy_name);

// DELETE /api/v1/security/policy/:name
struct MHD_Response *api_security_policy_delete(struct MHD_Connection *connection, const char *method, const char *policy_name);

// GET /api/v1/security/logs
struct MHD_Response *api_security_logs(struct MHD_Connection *connection, const char *method, const char *url);

// GET /api/v1/security/config
struct MHD_Response *api_security_config_get(struct MHD_Connection *connection, const char *method, const char *url);

// POST /api/v1/security/config
struct MHD_Response *api_security_config_save(struct MHD_Connection *connection, const char *method, const char *upload_data, size_t upload_data_size);

#endif // API_HANDLERS_H
