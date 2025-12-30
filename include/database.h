#ifndef DATABASE_H
#define DATABASE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Forward declare sqlite3 to avoid dependency in header
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

/**
 * Secure Database Layer using SQLCipher
 * Provides encrypted database with prepared statements for security
 */

// Database connection handle
struct database {
    sqlite3 *db;
    char db_path[512];
    char encryption_key[65];  // 64-char hex + null
    bool is_open;
    bool is_encrypted;
};

// Attack record structure
struct attack_record {
    int64_t id;
    int64_t timestamp;
    char src_ip[46];  // IPv6 max length
    char attack_type[32];
    int severity;
    uint32_t packets;
    uint64_t bytes;
    int duration;
    char status[16];
    time_t created_at;
};

// Traffic log structure
struct traffic_record {
    int64_t id;
    int64_t timestamp;
    char src_ip[46];
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t bytes;
    uint32_t packets;
    uint8_t direction;
    time_t created_at;
};

// Firewall rule structure
struct rule_record {
    int id;
    uint16_t port_start;
    uint16_t port_end;
    uint8_t protocol;
    uint8_t action;
    char description[256];
    bool enabled;
    time_t created_at;
};

// IP list entry (whitelist/blacklist)
struct ip_list_record {
    int id;
    char ip_address[46];
    uint8_t cidr_range;
    char list_type[16];  // "whitelist" or "blacklist"
    char reason[256];
    time_t expires_at;
    time_t created_at;
};

// GeoIP rule structure
struct geo_rule_record {
    int id;
    char country_code[3];
    char continent_code[3];
    char action[16];  // "allow" or "block"
    int priority;
    time_t created_at;
};

// Session structure
struct session_record {
    int id;
    char user_id[37];
    char session_id[37];
    char token[65];
    time_t expires_at;
    time_t created_at;
};

// Analytics hourly aggregate
struct analytics_hourly {
    time_t timestamp;
    uint64_t total_packets;
    uint64_t total_bytes;
    int attack_count;
    int unique_sources;
    char top_attacker[46];
    char top_protocol[16];
};

/**
 * Initialize database connection
 * @param db Database handle to initialize
 * @param db_path Path to database file
 * @param master_key_path Path to master encryption key file
 * @return 0 on success, -1 on error
 */
int database_init(struct database *db, const char *db_path, const char *master_key_path);

/**
 * Open database connection with encryption
 * @param db Database handle
 * @return 0 on success, -1 on error
 */
int database_open(struct database *db);

/**
 * Close database connection
 * @param db Database handle
 */
void database_close(struct database *db);

/**
 * Create/migrate database schema
 * @param db Database handle
 * @return 0 on success, -1 on error
 */
int database_create_schema(struct database *db);

/**
 * Check database integrity
 * @param db Database handle
 * @return 0 if OK, -1 on error
 */
int database_check_integrity(struct database *db);

/**
 * Begin transaction
 * @param db Database handle
 * @return 0 on success, -1 on error
 */
int database_begin_transaction(struct database *db);

/**
 * Commit transaction
 * @param db Database handle
 * @return 0 on success, -1 on error
 */
int database_commit_transaction(struct database *db);

/**
 * Rollback transaction
 * @param db Database handle
 * @return 0 on success, -1 on error
 */
int database_rollback_transaction(struct database *db);

// Attack record operations
int database_insert_attack(struct database *db, const struct attack_record *attack);
int database_get_attack(struct database *db, int64_t id, struct attack_record *attack);
int database_list_attacks(struct database *db, struct attack_record **attacks, int *count, int limit, int offset);
int database_get_attacks_history(struct database *db, struct attack_record **attacks, int *count, int limit);
int database_update_attack_status(struct database *db, int64_t id, const char *status);
int database_delete_old_attacks(struct database *db, time_t older_than);

// Traffic record operations
int database_insert_traffic(struct database *db, const struct traffic_record *traffic);
int database_list_traffic(struct database *db, struct traffic_record **traffic, int *count, 
                          time_t from, time_t to, int limit);
int database_get_traffic_stats(struct database *db, time_t from, time_t to,
                               uint64_t *total_packets, uint64_t *total_bytes);

// Rule operations
int database_insert_rule(struct database *db, const struct rule_record *rule);
int database_get_rule(struct database *db, int id, struct rule_record *rule);
int database_list_rules(struct database *db, struct rule_record **rules, int *count);
int database_update_rule(struct database *db, int id, const struct rule_record *rule);
int database_delete_rule(struct database *db, int id);
int database_toggle_rule(struct database *db, int id, bool enabled);

// IP list operations
int database_insert_ip_list(struct database *db, const struct ip_list_record *entry);
int database_delete_ip_list(struct database *db, int id);
int database_list_whitelist(struct database *db, struct ip_list_record **entries, int *count);
int database_list_blacklist(struct database *db, struct ip_list_record **entries, int *count);
int database_check_ip_in_list(struct database *db, const char *ip, const char *list_type, bool *found);

// GeoIP rule operations
int database_insert_geo_rule(struct database *db, const struct geo_rule_record *rule);
int database_delete_geo_rule(struct database *db, int id);
int database_list_geo_rules(struct database *db, struct geo_rule_record **rules, int *count);
int database_get_geo_action(struct database *db, const char *country_code, char *action);

// Session operations
int database_insert_session(struct database *db, const struct session_record *session);
int database_get_session(struct database *db, const char *token, struct session_record *session);
int database_delete_session(struct database *db, const char *token);
int database_delete_expired_sessions(struct database *db);

// Analytics operations
// API Key structure
struct api_key_record {
    int id;
    char name[64];
    char key_hash[128]; // SHA-256 or similar
    char key_prefix[8]; // First 4-7 chars for identification
    char permissions[64];
    time_t last_used_at;
    time_t expires_at;
    time_t created_at;
};

// ... Analytics operations ...
int database_insert_analytics_hourly(struct database *db, const struct analytics_hourly *analytics);
int database_get_analytics_summary(struct database *db, time_t from, time_t to,
                                   struct analytics_hourly *summary);

// API Key operations
int database_create_api_key(struct database *db, const struct api_key_record *key);
int database_list_api_keys(struct database *db, struct api_key_record **keys, int *count);
int database_delete_api_key(struct database *db, int id);
int database_validate_api_key(struct database *db, const char *key_hash, struct api_key_record *key_details);
int database_update_api_key_last_used(struct database *db, int id);
void database_free_api_key_list(struct api_key_record *keys, int count);

// Config operations
int database_set_config(struct database *db, const char *key, const char *value);
int database_get_config(struct database *db, const char *key, char *value, size_t value_len);

// Security Event structure (Tetragon integration)
struct security_event_record {
    int64_t id;
    int64_t timestamp;
    char event_type[64];
    int severity;
    char process_name[256];
    int pid;
    int ppid;
    int uid;
    char command[2048];
    char binary_path[4096];
    char parent_binary[4096];
    char action[32];
    char policy_name[128];
    char src_ip[46];
    char dst_ip[46];
    int dst_port;
    char file_path[4096];
    char file_operation[32];
    char metadata[8192];
    time_t created_at;
};

// Attack correlation structure
struct attack_correlation_record {
    int64_t id;
    int64_t timestamp;
    char attack_type[64];
    float confidence_score;
    int64_t network_event_id;
    int64_t security_event_id;
    char description[1024];
    char source_ip[46];
    char details[4096];
    time_t created_at;
};

// Security event operations
int db_insert_security_event(int64_t timestamp, const char *event_type, int severity,
                              const char *process_name, int pid, int ppid, int uid,
                              const char *command, const char *binary_path, 
                              const char *parent_binary, const char *action,
                              const char *policy_name, const char *src_ip, 
                              const char *dst_ip, int dst_port, const char *file_path,
                              const char *file_operation, const char *metadata);

int database_list_security_events(struct database *db, struct security_event_record **events,
                                   int *count, int severity_min, const char *event_type,
                                   time_t from, time_t to, int limit, int offset);

int database_get_security_stats(struct database *db, time_t from, time_t to,
                                 int *total_events, int *critical_alerts, 
                                 int *events_blocked);

int database_delete_old_security_events(struct database *db, time_t older_than);

// Attack correlation operations
int database_insert_attack_correlation(struct database *db, 
                                        const struct attack_correlation_record *corr);

int database_list_attack_correlations(struct database *db,
                                       struct attack_correlation_record **corrs,
                                       int *count, float min_confidence,
                                       time_t from, time_t to, int limit);

// Utility functions
void database_free_attack_list(struct attack_record *attacks, int count);
void database_free_traffic_list(struct traffic_record *traffic, int count);
void database_free_rule_list(struct rule_record *rules, int count);
void database_free_ip_list(struct ip_list_record *entries, int count);
void database_free_geo_rule_list(struct geo_rule_record *rules, int count);
void database_free_security_event_list(struct security_event_record *events, int count);
void database_free_correlation_list(struct attack_correlation_record *corrs, int count);

#endif // DATABASE_H
