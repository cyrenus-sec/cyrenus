#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>
#include "../include/database.h"

// Define SQL calls if not using SQLCipher specific headers
#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC
#endif

// Private helper prototypes
static int run_sql(sqlite3 *db, const char *sql);
static void log_error(const char *msg, const char *err);

// --- Core Database Functions ---

int database_init(struct database *db, const char *db_path, const char *master_key_path) {
    if (!db || !db_path || !master_key_path) return -1;

    memset(db, 0, sizeof(struct database));
    strncpy(db->db_path, db_path, sizeof(db->db_path) - 1);

    // Read master key
    FILE *f = fopen(master_key_path, "r");
    if (f) {
        if (fgets(db->encryption_key, sizeof(db->encryption_key), f)) {
            // Remove newline
            char *pos;
            if ((pos = strchr(db->encryption_key, '\n')) != NULL)
                *pos = '\0';
            db->is_encrypted = true;
        }
        fclose(f);
    } else {
        fprintf(stderr, "Warning: Could not read master key from %s. Database will not be encrypted.\n", master_key_path);
        db->is_encrypted = false;
    }

    // Ensure directory exists
    char *dir_end = strrchr(db->db_path, '/');
    if (dir_end) {
        char dir_path[512];
        int len = dir_end - db->db_path;
        strncpy(dir_path, db->db_path, len);
        dir_path[len] = '\0';
        
        struct stat st = {0};
        if (stat(dir_path, &st) == -1) {
            mkdir(dir_path, 0700);
        }
    }

    return 0;
}

int database_open(struct database *db) {
    if (db->is_open) return 0;

    int rc = sqlite3_open(db->db_path, &db->db);
    if (rc) {
        log_error("Can't open database", sqlite3_errmsg(db->db));
        return -1;
    }

    // Apply encryption if key exists
    if (db->is_encrypted && strlen(db->encryption_key) > 0) {
        // SQLCipher specific pragma to set the key
        char pragma_sql[128];
        snprintf(pragma_sql, sizeof(pragma_sql), "PRAGMA key = '%s';", db->encryption_key);
        if (sqlite3_exec(db->db, pragma_sql, NULL, NULL, NULL) != SQLITE_OK) {
             log_error("Failed to set encryption key", sqlite3_errmsg(db->db));
             sqlite3_close(db->db);
             return -1;
        }
    }

    // Enable WAL mode for better concurrency
    run_sql(db->db, "PRAGMA journal_mode=WAL;");
    run_sql(db->db, "PRAGMA synchronous=NORMAL;");
    run_sql(db->db, "PRAGMA foreign_keys=ON;");

    db->is_open = true;
    
    // Check if valid (verifies encryption key)
    if (sqlite3_exec(db->db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) != SQLITE_OK) {
        log_error("Database encryption check failed (wrong key?)", sqlite3_errmsg(db->db));
        database_close(db);
        return -1;
    }

    return 0;
}

void database_close(struct database *db) {
    if (db->db) {
        sqlite3_close(db->db);
        db->db = NULL;
    }
    db->is_open = false;
}

int database_create_schema(struct database *db) {
    const char *schema_sql = 
        "CREATE TABLE IF NOT EXISTS attacks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp INTEGER NOT NULL,"
        "src_ip TEXT NOT NULL,"
        "attack_type TEXT NOT NULL,"
        "severity INTEGER,"
        "packets INTEGER,"
        "bytes INTEGER,"
        "duration INTEGER,"
        "status TEXT,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS traffic_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp INTEGER NOT NULL,"
        "src_ip TEXT,"
        "dst_ip TEXT,"
        "src_port INTEGER,"
        "dst_port INTEGER,"
        "protocol INTEGER,"
        "bytes INTEGER,"
        "packets INTEGER,"
        "direction INTEGER,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS rules ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "port_start INTEGER,"
        "port_end INTEGER,"
        "protocol INTEGER,"
        "action INTEGER,"
        "description TEXT,"
        "enabled INTEGER DEFAULT 1,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS ip_lists ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip_address TEXT NOT NULL,"
        "cidr_range INTEGER,"
        "list_type TEXT CHECK(list_type IN ('whitelist', 'blacklist')),"
        "reason TEXT,"
        "expires_at INTEGER,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS geo_rules ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "country_code TEXT,"
        "continent_code TEXT,"
        "action TEXT CHECK(action IN ('allow', 'block')),"
        "priority INTEGER,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS sessions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id TEXT NOT NULL,"
        "session_id TEXT UNIQUE NOT NULL,"
        "token TEXT NOT NULL,"
        "expires_at INTEGER NOT NULL,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS config ("
        "key TEXT PRIMARY KEY,"
        "value TEXT,"
        "updated_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"
        
        "CREATE TABLE IF NOT EXISTS analytics_hourly ("
        "timestamp INTEGER PRIMARY KEY,"
        "total_packets INTEGER,"
        "total_bytes INTEGER,"
        "attack_count INTEGER,"
        "unique_sources INTEGER,"
        "top_attacker TEXT,"
        "top_protocol TEXT"
        ");"
        
        "CREATE TABLE IF NOT EXISTS api_keys ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT,"
        "key_hash TEXT NOT NULL,"
        "key_prefix TEXT,"
        "permissions TEXT,"
        "last_used_at INTEGER,"
        "expires_at INTEGER,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"
        
        "CREATE TABLE IF NOT EXISTS security_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp INTEGER NOT NULL,"
        "event_type TEXT NOT NULL,"
        "severity INTEGER NOT NULL,"
        "process_name TEXT,"
        "pid INTEGER,"
        "ppid INTEGER,"
        "uid INTEGER,"
        "command TEXT,"
        "binary_path TEXT,"
        "parent_binary TEXT,"
        "action TEXT,"
        "policy_name TEXT,"
        "src_ip TEXT,"
        "dst_ip TEXT,"
        "dst_port INTEGER,"
        "file_path TEXT,"
        "file_operation TEXT,"
        "metadata TEXT,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"
        
        "CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity);"
        "CREATE INDEX IF NOT EXISTS idx_security_type ON security_events(event_type);"
        
        "CREATE TABLE IF NOT EXISTS attack_correlation ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp INTEGER NOT NULL,"
        "attack_type TEXT NOT NULL,"
        "confidence_score REAL,"
        "network_event_id INTEGER,"
        "security_event_id INTEGER,"
        "description TEXT,"
        "source_ip TEXT,"
        "details TEXT,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");";

    if (sqlite3_exec(db->db, schema_sql, NULL, NULL, NULL) != SQLITE_OK) {
        log_error("Failed to create schema", sqlite3_errmsg(db->db));
        return -1;
    }

    return 0;
}

int database_check_integrity(struct database *db) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, "PRAGMA integrity_check;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text && strcmp((const char*)text, "ok") == 0) {
            result = 0;
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

int database_begin_transaction(struct database *db) {
    return run_sql(db->db, "BEGIN TRANSACTION;");
}

int database_commit_transaction(struct database *db) {
    return run_sql(db->db, "COMMIT;");
}

int database_rollback_transaction(struct database *db) {
    return run_sql(db->db, "ROLLBACK;");
}

// --- Attack Operations ---

int database_insert_attack(struct database *db, const struct attack_record *attack) {
    const char *sql = "INSERT INTO attacks (timestamp, src_ip, attack_type, severity, packets, bytes, duration, status) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, attack->timestamp);
    sqlite3_bind_text(stmt, 2, attack->src_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, attack->attack_type, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, attack->severity);
    sqlite3_bind_int(stmt, 5, attack->packets);
    sqlite3_bind_int64(stmt, 6, attack->bytes);
    sqlite3_bind_int(stmt, 7, attack->duration);
    sqlite3_bind_text(stmt, 8, attack->status, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_list_attacks(struct database *db, struct attack_record **attacks, int *count, int limit, int offset) {
    const char *sql = "SELECT id, timestamp, src_ip, attack_type, severity, packets, bytes, duration, status, created_at "
                      "FROM attacks ORDER BY timestamp DESC LIMIT ? OFFSET ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    struct attack_record *list = malloc(sizeof(struct attack_record) * limit);
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        list[idx].id = sqlite3_column_int64(stmt, 0);
        list[idx].timestamp = sqlite3_column_int64(stmt, 1);
        strncpy(list[idx].src_ip, (const char*)sqlite3_column_text(stmt, 2), sizeof(list[idx].src_ip)-1);
        strncpy(list[idx].attack_type, (const char*)sqlite3_column_text(stmt, 3), sizeof(list[idx].attack_type)-1);
        list[idx].severity = sqlite3_column_int(stmt, 4);
        list[idx].packets = sqlite3_column_int(stmt, 5);
        list[idx].bytes = sqlite3_column_int64(stmt, 6);
        list[idx].duration = sqlite3_column_int(stmt, 7);
        strncpy(list[idx].status, (const char*)sqlite3_column_text(stmt, 8), sizeof(list[idx].status)-1);
        list[idx].created_at = sqlite3_column_int64(stmt, 9);
        idx++;
    }

    sqlite3_finalize(stmt);
    *attacks = list;
    *count = idx;
    return 0;
}

int database_get_attacks_history(struct database *db, struct attack_record **attacks, int *count, int limit) {
    return database_list_attacks(db, attacks, count, limit, 0);
}

// --- Traffic Operations ---

int database_insert_traffic(struct database *db, const struct traffic_record *traffic) {
    const char *sql = "INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, direction) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, traffic->timestamp);
    sqlite3_bind_text(stmt, 2, traffic->src_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, traffic->dst_ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, traffic->src_port);
    sqlite3_bind_int(stmt, 5, traffic->dst_port);
    sqlite3_bind_int(stmt, 6, traffic->protocol);
    sqlite3_bind_int64(stmt, 7, traffic->bytes);
    sqlite3_bind_int(stmt, 8, traffic->packets);
    sqlite3_bind_int(stmt, 9, traffic->direction);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// --- IP List Operations ---

int database_insert_ip_list(struct database *db, const struct ip_list_record *entry) {
    const char *sql = "INSERT INTO ip_lists (ip_address, cidr_range, list_type, reason, expires_at) "
                      "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, entry->ip_address, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, entry->cidr_range);
    sqlite3_bind_text(stmt, 3, entry->list_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->reason, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, entry->expires_at);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_check_ip_in_list(struct database *db, const char *ip, const char *list_type, bool *found) {
    const char *sql = "SELECT id FROM ip_lists WHERE ip_address = ? AND list_type = ? "
                      "AND (expires_at IS NULL OR expires_at > ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, list_type, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, time(NULL));

    *found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *found = true;
    }
    sqlite3_finalize(stmt);
    return 0;
}

// --- Session Operations (Basic) ---

int database_insert_session(struct database *db, const struct session_record *session) {
    const char *sql = "INSERT INTO sessions (user_id, session_id, token, expires_at) VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, session->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, session->session_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, session->token, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, session->expires_at);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_get_session(struct database *db, const char *token, struct session_record *session) {
    const char *sql = "SELECT id, user_id, session_id, token, expires_at, created_at FROM sessions WHERE token = ? AND expires_at > ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, time(NULL));

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        session->id = sqlite3_column_int(stmt, 0);
        strncpy(session->user_id, (const char*)sqlite3_column_text(stmt, 1), sizeof(session->user_id)-1);
        strncpy(session->session_id, (const char*)sqlite3_column_text(stmt, 2), sizeof(session->session_id)-1);
        strncpy(session->token, (const char*)sqlite3_column_text(stmt, 3), sizeof(session->token)-1);
        session->expires_at = sqlite3_column_int64(stmt, 4);
        session->created_at = sqlite3_column_int64(stmt, 5);
        sqlite3_finalize(stmt);
        return 0; // Found
    }

    sqlite3_finalize(stmt);
    return -1; // Not found
}

// --- Helper implementations ---

static int run_sql(sqlite3 *db, const char *sql) {
    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        log_error("SQL error", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

static void log_error(const char *msg, const char *err) {
    fprintf(stderr, "[Database Error] %s: %s\n", msg, err ? err : "Unknown error");
}

// --- Utility implementation ---
// --- API Key Operations ---

int database_create_api_key(struct database *db, const struct api_key_record *key) {
    const char *sql = "INSERT INTO api_keys (name, key_hash, key_prefix, permissions, expires_at) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, key->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, key->key_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, key->key_prefix, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, key->permissions, -1, SQLITE_STATIC);
    if (key->expires_at > 0)
        sqlite3_bind_int64(stmt, 5, key->expires_at);
    else
        sqlite3_bind_null(stmt, 5);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_list_api_keys(struct database *db, struct api_key_record **keys, int *count) {
    const char *sql = "SELECT id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at FROM api_keys ORDER BY created_at DESC;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    // Count rows first or just realloc? We'll realloc for flexibility or do two passes.
    // Two passes is slower but safer for simple C. Or just guess/limit.
    // Let's use a dynamic array approach with realloc.
    
    int capacity = 10;
    int size = 0;
    struct api_key_record *list = malloc(sizeof(struct api_key_record) * capacity);
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (size >= capacity) {
            capacity *= 2;
            struct api_key_record *tmp = realloc(list, sizeof(struct api_key_record) * capacity);
            if (!tmp) {
                free(list);
                sqlite3_finalize(stmt);
                return -1;
            }
            list = tmp;
        }

        list[size].id = sqlite3_column_int(stmt, 0);
        const char *name = (const char*)sqlite3_column_text(stmt, 1);
        strncpy(list[size].name, name ? name : "", sizeof(list[size].name)-1);
        
        const char *hash = (const char*)sqlite3_column_text(stmt, 2);
        strncpy(list[size].key_hash, hash ? hash : "", sizeof(list[size].key_hash)-1); // Usually hidden in UI
        
        const char *prefix = (const char*)sqlite3_column_text(stmt, 3);
        strncpy(list[size].key_prefix, prefix ? prefix : "", sizeof(list[size].key_prefix)-1);
        
        const char *perms = (const char*)sqlite3_column_text(stmt, 4);
        strncpy(list[size].permissions, perms ? perms : "", sizeof(list[size].permissions)-1);
        
        list[size].last_used_at = sqlite3_column_int64(stmt, 5);
        list[size].expires_at = sqlite3_column_int64(stmt, 6);
        list[size].created_at = sqlite3_column_int64(stmt, 7);
        
        size++;
    }

    sqlite3_finalize(stmt);
    *keys = list;
    *count = size;
    return 0;
}

int database_delete_api_key(struct database *db, int id) {
    const char *sql = "DELETE FROM api_keys WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_validate_api_key(struct database *db, const char *key_hash, struct api_key_record *key_details) {
    const char *sql = "SELECT id, name, permissions FROM api_keys WHERE key_hash = ? AND (expires_at IS NULL OR expires_at > ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, key_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, time(NULL));

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (key_details) {
            key_details->id = sqlite3_column_int(stmt, 0);
            const char *name = (const char*)sqlite3_column_text(stmt, 1);
            strncpy(key_details->name, name ? name : "", sizeof(key_details->name)-1);
            const char *perms = (const char*)sqlite3_column_text(stmt, 2);
            strncpy(key_details->permissions, perms ? perms : "", sizeof(key_details->permissions)-1);
        }
        sqlite3_finalize(stmt);
        return 0; // Valid
    }

    sqlite3_finalize(stmt);
    return -1; // Invalid
}

int database_update_api_key_last_used(struct database *db, int id) {
    const char *sql = "UPDATE api_keys SET last_used_at = ? WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, time(NULL));
    sqlite3_bind_int(stmt, 2, id); // Use ID obtained from validation
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

void database_free_api_key_list(struct api_key_record *keys, int count) {
    if (keys) free(keys);
}

void database_free_attack_list(struct attack_record *attacks, int count) {
    if (attacks) free(attacks);
}

// --- Security Event Operations (Tetragon Integration) ---

extern struct database *g_db; // Global database handle defined in main.c

int db_insert_security_event(int64_t timestamp, const char *event_type, int severity,
                              const char *process_name, int pid, int ppid, int uid,
                              const char *command, const char *binary_path,
                              const char *parent_binary, const char *action,
                              const char *policy_name, const char *src_ip,
                              const char *dst_ip, int dst_port, const char *file_path,
                              const char *file_operation, const char *metadata) {
    if (!g_db || !g_db->is_open) return -1;
    
    const char *sql = 
        "INSERT INTO security_events ("
        "timestamp, event_type, severity, process_name, pid, ppid, uid, "
        "command, binary_path, parent_binary, action, policy_name, "
        "src_ip, dst_ip, dst_port, file_path, file_operation, metadata"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, severity);
    sqlite3_bind_text(stmt, 4, process_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, pid);
    sqlite3_bind_int(stmt, 6, ppid);
    sqlite3_bind_int(stmt, 7, uid);
    sqlite3_bind_text(stmt, 8, command, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, binary_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, parent_binary, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, policy_name, -1, SQLITE_TRANSIENT);
    
    if (src_ip) sqlite3_bind_text(stmt, 13, src_ip, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 13);
    
    if (dst_ip) sqlite3_bind_text(stmt, 14, dst_ip, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 14);
    
    if (dst_port > 0) sqlite3_bind_int(stmt, 15, dst_port);
    else sqlite3_bind_null(stmt, 15);
    
    if (file_path) sqlite3_bind_text(stmt, 16, file_path, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 16);
    
    if (file_operation) sqlite3_bind_text(stmt, 17, file_operation, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 17);
    
    if (metadata) sqlite3_bind_text(stmt, 18, metadata, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 18);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_list_security_events(struct database *db, struct security_event_record **events,
                                   int *count, int severity_min, const char *event_type,
                                   time_t from, time_t to, int limit, int offset) {
    if (!db || !db->is_open) return -1;
    
    // Build dynamic SQL based on filters
    char sql[1024];
    
    strcpy(sql, "SELECT id, timestamp, event_type, severity, process_name, pid, ppid, uid, "
                "command, binary_path, parent_binary, action, policy_name, src_ip, dst_ip, "
                "dst_port, file_path, file_operation, metadata, created_at "
                "FROM security_events WHERE 1=1");
    
    if (severity_min > 0) {
        strcat(sql, " AND severity >= ?");
    }
    if (event_type) {
        strcat(sql, " AND event_type = ?");
    }
    if (from > 0) {
        strcat(sql, " AND timestamp >= ?");
    }
    if (to > 0) {
        strcat(sql, " AND timestamp <= ?");
    }
    
    strcat(sql, " ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    
    // Bind parameters
    int bind_idx = 1;
    if (severity_min > 0) {
        sqlite3_bind_int(stmt, bind_idx++, severity_min);
    }
    if (event_type) {
        sqlite3_bind_text(stmt, bind_idx++, event_type, -1, SQLITE_STATIC);
    }
    if (from > 0) {
        sqlite3_bind_int64(stmt, bind_idx++, from);
    }
    if (to > 0) {
        sqlite3_bind_int64(stmt, bind_idx++, to);
    }
    sqlite3_bind_int(stmt, bind_idx++, limit);
    sqlite3_bind_int(stmt, bind_idx++, offset);
    
    // Allocate result array
    struct security_event_record *list = malloc(sizeof(struct security_event_record) * limit);
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        list[idx].id = sqlite3_column_int64(stmt, 0);
        list[idx].timestamp = sqlite3_column_int64(stmt, 1);
        strncpy(list[idx].event_type, (const char*)sqlite3_column_text(stmt, 2), sizeof(list[idx].event_type)-1);
        list[idx].severity = sqlite3_column_int(stmt, 3);
        
        const char *pname = (const char*)sqlite3_column_text(stmt, 4);
        if (pname) strncpy(list[idx].process_name, pname, sizeof(list[idx].process_name)-1);
        
        list[idx].pid = sqlite3_column_int(stmt, 5);
        list[idx].ppid = sqlite3_column_int(stmt, 6);
        list[idx].uid = sqlite3_column_int(stmt, 7);
        
        const char *cmd = (const char*)sqlite3_column_text(stmt, 8);
        if (cmd) strncpy(list[idx].command, cmd, sizeof(list[idx].command)-1);
        
        const char *bin = (const char*)sqlite3_column_text(stmt, 9);
        if (bin) strncpy(list[idx].binary_path, bin, sizeof(list[idx].binary_path)-1);
        
        const char *parent = (const char*)sqlite3_column_text(stmt, 10);
        if (parent) strncpy(list[idx].parent_binary, parent, sizeof(list[idx].parent_binary)-1);
        
        const char *act = (const char*)sqlite3_column_text(stmt, 11);
        if (act) strncpy(list[idx].action, act, sizeof(list[idx].action)-1);
        
        const char *policy = (const char*)sqlite3_column_text(stmt, 12);
        if (policy) strncpy(list[idx].policy_name, policy, sizeof(list[idx].policy_name)-1);
        
        const char *sip = (const char*)sqlite3_column_text(stmt, 13);
        if (sip) strncpy(list[idx].src_ip, sip, sizeof(list[idx].src_ip)-1);
        
        const char *dip = (const char*)sqlite3_column_text(stmt, 14);
        if (dip) strncpy(list[idx].dst_ip, dip, sizeof(list[idx].dst_ip)-1);
        
        list[idx].dst_port = sqlite3_column_int(stmt, 15);
        
        const char *fpath = (const char*)sqlite3_column_text(stmt, 16);
        if (fpath) strncpy(list[idx].file_path, fpath, sizeof(list[idx].file_path)-1);
        
        const char *fop = (const char*)sqlite3_column_text(stmt, 17);
        if (fop) strncpy(list[idx].file_operation, fop, sizeof(list[idx].file_operation)-1);
        
        const char *meta = (const char*)sqlite3_column_text(stmt, 18);
        if (meta) strncpy(list[idx].metadata, meta, sizeof(list[idx].metadata)-1);
        
        list[idx].created_at = sqlite3_column_int64(stmt, 19);
        idx++;
    }
    
    sqlite3_finalize(stmt);
    *events = list;
    *count = idx;
    return 0;
}

int database_get_security_stats(struct database *db, time_t from, time_t to,
                                 int *total_events, int *critical_alerts,
                                 int *events_blocked) {
    if (!db || !db->is_open) return -1;
    
    const char *sql =
        "SELECT "
        "COUNT(*) as total, "
        "SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END) as critical, "
        "SUM(CASE WHEN action IN ('Sigkill', 'block') THEN 1 ELSE 0 END) as blocked "
        "FROM security_events "
        "WHERE timestamp >= ? AND timestamp <= ?";
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, from);
    sqlite3_bind_int64(stmt, 2, to);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *total_events = sqlite3_column_int(stmt, 0);
        *critical_alerts = sqlite3_column_int(stmt, 1);
        *events_blocked = sqlite3_column_int(stmt, 2);
        sqlite3_finalize(stmt);
        return 0;
    }
    
    sqlite3_finalize(stmt);
    return -1;
}

int database_delete_old_security_events(struct database *db, time_t older_than) {
    if (!db || !db->is_open) return -1;
    
    const char *sql = "DELETE FROM security_events WHERE timestamp < ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, older_than);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_insert_attack_correlation(struct database *db,
                                        const struct attack_correlation_record *corr) {
    if (!db || !db->is_open || !corr) return -1;
    
    const char *sql =
        "INSERT INTO attack_correlation ("
        "timestamp, attack_type, confidence_score, network_event_id, "
        "security_event_id, description, source_ip, details"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, corr->timestamp);
    sqlite3_bind_text(stmt, 2, corr->attack_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 3, corr->confidence_score);
    sqlite3_bind_int64(stmt, 4, corr->network_event_id);
    sqlite3_bind_int64(stmt, 5, corr->security_event_id);
    sqlite3_bind_text(stmt, 6, corr->description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, corr->source_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, corr->details, -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_list_attack_correlations(struct database *db,
                                       struct attack_correlation_record **corrs,
                                       int *count, float min_confidence,
                                       time_t from, time_t to, int limit) {
    if (!db || !db->is_open) return -1;
    
    const char *sql =
        "SELECT id, timestamp, attack_type, confidence_score, network_event_id, "
        "security_event_id, description, source_ip, details, created_at "
        "FROM attack_correlation "
        "WHERE confidence_score >= ? AND timestamp >= ? AND timestamp <= ? "
        "ORDER BY timestamp DESC LIMIT ?";
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_double(stmt, 1, min_confidence);
    sqlite3_bind_int64(stmt, 2, from);
    sqlite3_bind_int64(stmt, 3, to);
    sqlite3_bind_int(stmt, 4, limit);
    
    struct attack_correlation_record *list = malloc(sizeof(struct attack_correlation_record) * limit);
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        list[idx].id = sqlite3_column_int64(stmt, 0);
        list[idx].timestamp = sqlite3_column_int64(stmt, 1);
        strncpy(list[idx].attack_type, (const char*)sqlite3_column_text(stmt, 2),
                sizeof(list[idx].attack_type)-1);
        list[idx].confidence_score = sqlite3_column_double(stmt, 3);
        list[idx].network_event_id = sqlite3_column_int64(stmt, 4);
        list[idx].security_event_id = sqlite3_column_int64(stmt, 5);
        strncpy(list[idx].description, (const char*)sqlite3_column_text(stmt, 6),
                sizeof(list[idx].description)-1);
        strncpy(list[idx].source_ip, (const char*)sqlite3_column_text(stmt, 7),
                sizeof(list[idx].source_ip)-1);
        strncpy(list[idx].details, (const char*)sqlite3_column_text(stmt, 8),
                sizeof(list[idx].details)-1);
        list[idx].created_at = sqlite3_column_int64(stmt, 9);
        idx++;
    }
    
    sqlite3_finalize(stmt);
    *corrs = list;
    *count = idx;
    return 0;
}

void database_free_security_event_list(struct security_event_record *events, int count) {
    if (events) free(events);
}

void database_free_correlation_list(struct attack_correlation_record *corrs, int count) {
    if (corrs) free(corrs);
}
