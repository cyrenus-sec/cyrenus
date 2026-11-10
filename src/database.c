#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC
#endif
#include <sqlite3.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>
#include "../include/database.h"

extern struct database *g_db;

// Private helper prototypes
static int run_sql(sqlite3 *db, const char *sql);
static void log_error(const char *msg, const char *err);

static void db_lock(struct database *db) {
    if (db && db->mutex_initialized) {
        pthread_mutex_lock(&db->mutex);
    }
}

static void db_unlock(struct database *db) {
    if (db && db->mutex_initialized) {
        pthread_mutex_unlock(&db->mutex);
    }
}

static void safe_col_copy(sqlite3_stmt *stmt, int col, char *dst, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    const unsigned char *txt = sqlite3_column_text(stmt, col);
    if (txt) {
        snprintf(dst, dst_size, "%s", (const char *)txt);
    } else {
        dst[0] = '\0';
    }
}

static int ensure_column_exists(struct database *db, const char *table, const char *column, const char *col_def) {
    char pragma[256];
    snprintf(pragma, sizeof(pragma), "PRAGMA table_info(%s);", table);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, pragma, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    bool found = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *cname = sqlite3_column_text(stmt, 1);
        if (cname && strcmp((const char *)cname, column) == 0) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(stmt);

    if (!found) {
        char alter_sql[512];
        snprintf(alter_sql, sizeof(alter_sql), "ALTER TABLE %s ADD COLUMN %s %s;", table, column, col_def);
        return run_sql(db->db, alter_sql);
    }
    return 0;
}

// --- Core Database Functions ---

int database_init(struct database *db, const char *db_path, const char *master_key_path) {
    if (!db || !db_path || !master_key_path) return -1;

    memset(db, 0, sizeof(struct database));
    snprintf(db->db_path, sizeof(db->db_path), "%s", db_path);

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) == 0) {
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        if (pthread_mutex_init(&db->mutex, &attr) == 0) {
            db->mutex_initialized = true;
        }
        pthread_mutexattr_destroy(&attr);
    }
    if (!db->mutex_initialized && pthread_mutex_init(&db->mutex, NULL) == 0) {
        db->mutex_initialized = true;
    }

    // Read master key
    FILE *f = fopen(master_key_path, "r");
    if (f) {
        if (fgets(db->encryption_key, sizeof(db->encryption_key), f)) {
            char *pos;
            if ((pos = strchr(db->encryption_key, '\n')) != NULL) *pos = '\0';
            if ((pos = strchr(db->encryption_key, '\r')) != NULL) *pos = '\0';
            db->is_encrypted = strlen(db->encryption_key) > 0;
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
        size_t len = (size_t)(dir_end - db->db_path);
        if (len > 0 && len < sizeof(dir_path)) {
            memcpy(dir_path, db->db_path, len);
            dir_path[len] = '\0';

            struct stat st = {0};
            if (stat(dir_path, &st) == -1) {
                mkdir(dir_path, 0700);
            }
        }
    }

    return 0;
}

int database_open(struct database *db) {
    if (!db) return -1;
    if (db->is_open) return 0;

    if (!db->mutex_initialized) {
        pthread_mutexattr_t attr;
        if (pthread_mutexattr_init(&attr) == 0) {
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            if (pthread_mutex_init(&db->mutex, &attr) == 0) {
                db->mutex_initialized = true;
            }
            pthread_mutexattr_destroy(&attr);
        }
    }

    db_lock(db);
    int rc = sqlite3_open(db->db_path, &db->db);
    if (rc) {
        log_error("Can't open database", db->db ? sqlite3_errmsg(db->db) : "open failed");
        if (db->db) {
            sqlite3_close(db->db);
            db->db = NULL;
        }
        db_unlock(db);
        return -1;
    }

    sqlite3_busy_timeout(db->db, 5000);

    // Apply encryption if key exists
    if (db->is_encrypted && strlen(db->encryption_key) > 0) {
        if (sqlite3_key(db->db, db->encryption_key, (int)strlen(db->encryption_key)) != SQLITE_OK) {
            log_error("Failed to set encryption key", sqlite3_errmsg(db->db));
            sqlite3_close(db->db);
            db->db = NULL;
            db_unlock(db);
            return -1;
        }
    }

    // Verify key / readability first
    if (sqlite3_exec(db->db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) != SQLITE_OK) {
        log_error("Database encryption check failed (wrong key?)", sqlite3_errmsg(db->db));
        sqlite3_close(db->db);
        db->db = NULL;
        db->is_open = false;
        db_unlock(db);
        return -1;
    }

    // Enable WAL mode for better concurrency
    run_sql(db->db, "PRAGMA journal_mode=WAL;");
    run_sql(db->db, "PRAGMA synchronous=NORMAL;");
    run_sql(db->db, "PRAGMA foreign_keys=ON;");

    db->is_open = true;
    db_unlock(db);
    return 0;
}

void database_close(struct database *db) {
    if (!db) return;
    db_lock(db);
    if (db->db) {
        sqlite3_close(db->db);
        db->db = NULL;
    }
    db->is_open = false;
    db_unlock(db);
    if (db->mutex_initialized) {
        pthread_mutex_destroy(&db->mutex);
        db->mutex_initialized = false;
    }
}

int database_create_schema(struct database *db) {
    if (!db || !db->is_open) return -1;

    const char *schema_sql =
        "CREATE TABLE IF NOT EXISTS attacks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp INTEGER NOT NULL,"
        "src_ip TEXT NOT NULL,"
        "attack_type TEXT NOT NULL,"
        "protocol TEXT DEFAULT 'UNKNOWN',"
        "severity INTEGER DEFAULT 2,"
        "packets INTEGER DEFAULT 0,"
        "bytes INTEGER DEFAULT 0,"
        "dropped_packets INTEGER DEFAULT 0,"
        "dropped_bytes INTEGER DEFAULT 0,"
        "peak_pps INTEGER DEFAULT 0,"
        "duration INTEGER DEFAULT 0,"
        "blocked INTEGER DEFAULT 0,"
        "status TEXT DEFAULT 'active',"
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
        "ip_address TEXT NOT NULL DEFAULT '0.0.0.0',"
        "port_start INTEGER DEFAULT 0,"
        "port_end INTEGER DEFAULT 0,"
        "protocol INTEGER DEFAULT 0,"
        "action INTEGER DEFAULT 1,"
        "description TEXT,"
        "enabled INTEGER DEFAULT 1,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS ip_lists ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip_address TEXT NOT NULL,"
        "cidr_range INTEGER DEFAULT 32,"
        "list_type TEXT CHECK(list_type IN ('whitelist', 'blacklist')),"
        "reason TEXT,"
        "expires_at INTEGER DEFAULT 0,"
        "created_at INTEGER DEFAULT (cast(strftime('%s','now') as int))"
        ");"

        "CREATE TABLE IF NOT EXISTS geo_rules ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "country_code TEXT UNIQUE NOT NULL,"
        "continent_code TEXT,"
        "action TEXT CHECK(action IN ('allow', 'block')),"
        "priority INTEGER DEFAULT 1,"
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

    db_lock(db);

    if (sqlite3_exec(db->db, schema_sql, NULL, NULL, NULL) != SQLITE_OK) {
        log_error("Failed to create schema", sqlite3_errmsg(db->db));
        db_unlock(db);
        return -1;
    }

    // Idempotent schema migrations for pre-existing DBs
    ensure_column_exists(db, "attacks", "protocol", "TEXT DEFAULT 'UNKNOWN'");
    ensure_column_exists(db, "attacks", "dropped_packets", "INTEGER DEFAULT 0");
    ensure_column_exists(db, "attacks", "dropped_bytes", "INTEGER DEFAULT 0");
    ensure_column_exists(db, "attacks", "peak_pps", "INTEGER DEFAULT 0");
    ensure_column_exists(db, "attacks", "blocked", "INTEGER DEFAULT 0");
    ensure_column_exists(db, "rules", "ip_address", "TEXT NOT NULL DEFAULT '0.0.0.0'");

    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);");
    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);");
    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_attacks_ip_type ON attacks(src_ip, attack_type);");
    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_rules_tuple ON rules(ip_address, port_start, protocol);");
    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_iplists_type ON ip_lists(list_type);");
    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_corr_timestamp ON attack_correlation(timestamp);");
    run_sql(db->db, "CREATE INDEX IF NOT EXISTS idx_corr_ip_type ON attack_correlation(source_ip, attack_type, timestamp);");

    db_unlock(db);
    return 0;
}

int database_check_integrity(struct database *db) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db->db, "PRAGMA integrity_check;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text && strcmp((const char *)text, "ok") == 0) {
            result = 0;
        }
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return result;
}

int database_begin_transaction(struct database *db) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    int rc = run_sql(db->db, "BEGIN TRANSACTION;");
    db_unlock(db);
    return rc;
}

int database_commit_transaction(struct database *db) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    int rc = run_sql(db->db, "COMMIT;");
    db_unlock(db);
    return rc;
}

int database_rollback_transaction(struct database *db) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    int rc = run_sql(db->db, "ROLLBACK;");
    db_unlock(db);
    return rc;
}

// --- Attack Operations ---

int database_insert_attack(struct database *db, const struct attack_record *attack) {
    if (!db || !db->is_open || !attack) return -1;
    db_lock(db);

    const char *sql =
        "INSERT INTO attacks (timestamp, src_ip, attack_type, protocol, severity, packets, bytes, "
        "dropped_packets, dropped_bytes, peak_pps, duration, blocked, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, attack->timestamp);
    sqlite3_bind_text(stmt, 2, attack->src_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, attack->attack_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, attack->protocol[0] ? attack->protocol : "UNKNOWN", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, attack->severity);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)attack->packets);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)attack->bytes);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)attack->dropped_packets);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)attack->dropped_bytes);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)attack->peak_pps);
    sqlite3_bind_int(stmt, 11, attack->duration);
    sqlite3_bind_int(stmt, 12, attack->blocked ? 1 : 0);
    sqlite3_bind_text(stmt, 13, attack->status[0] ? attack->status : "active", -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_upsert_active_attack(struct database *db, const struct attack_record *attack) {
    if (!db || !db->is_open || !attack) return -1;
    db_lock(db);

    const char *find_sql =
        "SELECT id, packets, bytes, dropped_packets, dropped_bytes, peak_pps, duration, severity, blocked "
        "FROM attacks "
        "WHERE src_ip = ? AND attack_type = ? AND status IN ('active', 'mitigated') "
        "AND timestamp >= ? "
        "ORDER BY id DESC LIMIT 1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    int64_t recent_cutoff = attack->timestamp - 300;
    sqlite3_bind_text(stmt, 1, attack->src_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, attack->attack_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, recent_cutoff);

    int64_t existing_id = -1;
    uint32_t old_pkts = 0, old_dpkts = 0, old_pps = 0;
    uint64_t old_bytes = 0, old_dbytes = 0;
    int old_dur = 0, old_sev = 0, old_blk = 0;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        existing_id = sqlite3_column_int64(stmt, 0);
        old_pkts = (uint32_t)sqlite3_column_int64(stmt, 1);
        old_bytes = (uint64_t)sqlite3_column_int64(stmt, 2);
        old_dpkts = (uint32_t)sqlite3_column_int64(stmt, 3);
        old_dbytes = (uint64_t)sqlite3_column_int64(stmt, 4);
        old_pps = (uint32_t)sqlite3_column_int64(stmt, 5);
        old_dur = sqlite3_column_int(stmt, 6);
        old_sev = sqlite3_column_int(stmt, 7);
        old_blk = sqlite3_column_int(stmt, 8);
    }
    sqlite3_finalize(stmt);

    if (existing_id < 0) {
        int rc = database_insert_attack(db, attack);
        db_unlock(db);
        return rc;
    }

    const char *upd_sql =
        "UPDATE attacks SET timestamp = ?, protocol = ?, severity = ?, packets = ?, bytes = ?, "
        "dropped_packets = ?, dropped_bytes = ?, peak_pps = ?, duration = ?, blocked = ?, status = ? "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(db->db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    uint32_t max_pkts = attack->packets > old_pkts ? attack->packets : old_pkts;
    uint64_t max_bytes = attack->bytes > old_bytes ? attack->bytes : old_bytes;
    uint32_t max_dpkts = attack->dropped_packets > old_dpkts ? attack->dropped_packets : old_dpkts;
    uint64_t max_dbytes = attack->dropped_bytes > old_dbytes ? attack->dropped_bytes : old_dbytes;
    uint32_t max_pps = attack->peak_pps > old_pps ? attack->peak_pps : old_pps;
    int max_dur = attack->duration > old_dur ? attack->duration : old_dur;
    int max_sev = attack->severity > old_sev ? attack->severity : old_sev;
    int merged_blk = (attack->blocked || old_blk) ? 1 : 0;

    sqlite3_bind_int64(stmt, 1, attack->timestamp);
    sqlite3_bind_text(stmt, 2, attack->protocol[0] ? attack->protocol : "UNKNOWN", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, max_sev);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)max_pkts);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)max_bytes);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)max_dpkts);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)max_dbytes);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)max_pps);
    sqlite3_bind_int(stmt, 9, max_dur);
    sqlite3_bind_int(stmt, 10, merged_blk);
    sqlite3_bind_text(stmt, 11, attack->status[0] ? attack->status : "active", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 12, existing_id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_finalize_stale_attacks(struct database *db, time_t active_cutoff_ts) {
    if (!db || !db->is_open) return -1;
    db_lock(db);

    const char *sql =
        "UPDATE attacks SET status = 'mitigated' "
        "WHERE status = 'active' AND timestamp < ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)active_cutoff_ts);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static void fill_attack_row(sqlite3_stmt *stmt, struct attack_record *rec) {
    rec->id = sqlite3_column_int64(stmt, 0);
    rec->timestamp = sqlite3_column_int64(stmt, 1);
    safe_col_copy(stmt, 2, rec->src_ip, sizeof(rec->src_ip));
    safe_col_copy(stmt, 3, rec->attack_type, sizeof(rec->attack_type));
    safe_col_copy(stmt, 4, rec->protocol, sizeof(rec->protocol));
    rec->severity = sqlite3_column_int(stmt, 5);
    rec->packets = (uint32_t)sqlite3_column_int64(stmt, 6);
    rec->bytes = (uint64_t)sqlite3_column_int64(stmt, 7);
    rec->dropped_packets = (uint32_t)sqlite3_column_int64(stmt, 8);
    rec->dropped_bytes = (uint64_t)sqlite3_column_int64(stmt, 9);
    rec->peak_pps = (uint32_t)sqlite3_column_int64(stmt, 10);
    rec->duration = sqlite3_column_int(stmt, 11);
    rec->blocked = sqlite3_column_int(stmt, 12) != 0;
    safe_col_copy(stmt, 13, rec->status, sizeof(rec->status));
    rec->created_at = sqlite3_column_int64(stmt, 14);
}

int database_get_attack(struct database *db, int64_t id, struct attack_record *attack) {
    if (!db || !db->is_open || !attack) return -1;
    memset(attack, 0, sizeof(*attack));
    db_lock(db);

    const char *sql =
        "SELECT id, timestamp, src_ip, attack_type, protocol, severity, packets, bytes, "
        "dropped_packets, dropped_bytes, peak_pps, duration, blocked, status, created_at "
        "FROM attacks WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, id);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        fill_attack_row(stmt, attack);
        res = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return res;
}

int64_t database_find_recent_attack_by_ip(struct database *db, const char *src_ip, time_t cutoff_ts) {
    if (!db || !db->is_open || !src_ip || !src_ip[0]) return 0;
    db_lock(db);

    const char *sql =
        "SELECT id FROM attacks "
        "WHERE src_ip = ? AND timestamp >= ? "
        "ORDER BY timestamp DESC, id DESC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, src_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)cutoff_ts);

    int64_t attack_id = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        attack_id = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return attack_id;
}

int database_list_attacks(struct database *db, struct attack_record **attacks, int *count, int limit, int offset) {
    if (!db || !db->is_open || !attacks || !count) return -1;
    *attacks = NULL;
    *count = 0;

    if (limit <= 0) limit = 50;
    if (limit > 10000) limit = 10000;
    if (offset < 0) offset = 0;

    db_lock(db);
    const char *sql =
        "SELECT id, timestamp, src_ip, attack_type, protocol, severity, packets, bytes, "
        "dropped_packets, dropped_bytes, peak_pps, duration, blocked, status, created_at "
        "FROM attacks ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    struct attack_record *list = calloc((size_t)limit, sizeof(struct attack_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        fill_attack_row(stmt, &list[idx]);
        idx++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *attacks = list;
    *count = idx;
    return 0;
}

int database_count_attacks(struct database *db, int *total_count) {
    if (!db || !db->is_open || !total_count) return -1;
    *total_count = 0;
    db_lock(db);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, "SELECT COUNT(*) FROM attacks;", -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *total_count = sqlite3_column_int(stmt, 0);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

int database_get_attacks_history(struct database *db, struct attack_record **attacks, int *count, int limit) {
    return database_list_attacks(db, attacks, count, limit, 0);
}

int database_update_attack_status(struct database *db, int64_t id, const char *status) {
    if (!db || !db->is_open || !status) return -1;
    db_lock(db);

    const char *sql = "UPDATE attacks SET status = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE && changes > 0) ? 0 : -1;
}

int database_delete_all_attacks(struct database *db) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    int rc = run_sql(db->db, "DELETE FROM attacks;");
    db_unlock(db);
    return rc;
}

int database_delete_old_attacks(struct database *db, time_t older_than) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM attacks WHERE timestamp < ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)older_than);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// --- Traffic Operations ---

int database_insert_traffic(struct database *db, const struct traffic_record *traffic) {
    if (!db || !db->is_open || !traffic) return -1;
    db_lock(db);
    const char *sql =
        "INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, direction) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, traffic->timestamp);
    sqlite3_bind_text(stmt, 2, traffic->src_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, traffic->dst_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, traffic->src_port);
    sqlite3_bind_int(stmt, 5, traffic->dst_port);
    sqlite3_bind_int(stmt, 6, traffic->protocol);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)traffic->bytes);
    sqlite3_bind_int(stmt, 8, (int)traffic->packets);
    sqlite3_bind_int(stmt, 9, traffic->direction);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_list_traffic(struct database *db, struct traffic_record **traffic, int *count,
                          time_t from, time_t to, int limit) {
    if (!db || !db->is_open || !traffic || !count) return -1;
    *traffic = NULL;
    *count = 0;
    if (limit <= 0) limit = 100;
    if (limit > 10000) limit = 10000;

    db_lock(db);
    const char *sql =
        "SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, direction, created_at "
        "FROM traffic_logs WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC LIMIT ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)from);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(to > 0 ? to : time(NULL)));
    sqlite3_bind_int(stmt, 3, limit);

    struct traffic_record *list = calloc((size_t)limit, sizeof(struct traffic_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        list[idx].id = sqlite3_column_int64(stmt, 0);
        list[idx].timestamp = sqlite3_column_int64(stmt, 1);
        safe_col_copy(stmt, 2, list[idx].src_ip, sizeof(list[idx].src_ip));
        safe_col_copy(stmt, 3, list[idx].dst_ip, sizeof(list[idx].dst_ip));
        list[idx].src_port = (uint16_t)sqlite3_column_int(stmt, 4);
        list[idx].dst_port = (uint16_t)sqlite3_column_int(stmt, 5);
        list[idx].protocol = (uint8_t)sqlite3_column_int(stmt, 6);
        list[idx].bytes = (uint64_t)sqlite3_column_int64(stmt, 7);
        list[idx].packets = (uint32_t)sqlite3_column_int(stmt, 8);
        list[idx].direction = (uint8_t)sqlite3_column_int(stmt, 9);
        list[idx].created_at = sqlite3_column_int64(stmt, 10);
        idx++;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    *traffic = list;
    *count = idx;
    return 0;
}

int database_get_traffic_stats(struct database *db, time_t from, time_t to,
                               uint64_t *total_packets, uint64_t *total_bytes) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql =
        "SELECT COALESCE(SUM(packets), 0), COALESCE(SUM(bytes), 0) "
        "FROM traffic_logs WHERE timestamp >= ? AND timestamp <= ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)from);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(to > 0 ? to : time(NULL)));

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (total_packets) *total_packets = (uint64_t)sqlite3_column_int64(stmt, 0);
        if (total_bytes) *total_bytes = (uint64_t)sqlite3_column_int64(stmt, 1);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

// --- Rule Operations ---

int database_insert_rule(struct database *db, const struct rule_record *rule) {
    if (!db || !db->is_open || !rule) return -1;
    db_lock(db);

    const char *ip = rule->ip_address[0] ? rule->ip_address : "0.0.0.0";

    // Remove existing duplicate tuple so updates behave as clean upsert
    const char *del_sql = "DELETE FROM rules WHERE ip_address = ? AND port_start = ? AND protocol = ?;";
    sqlite3_stmt *del_stmt = NULL;
    if (sqlite3_prepare_v2(db->db, del_sql, -1, &del_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(del_stmt, 1, ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(del_stmt, 2, rule->port_start);
        sqlite3_bind_int(del_stmt, 3, rule->protocol);
        sqlite3_step(del_stmt);
        sqlite3_finalize(del_stmt);
    }

    const char *sql =
        "INSERT INTO rules (ip_address, port_start, port_end, protocol, action, description, enabled) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, rule->port_start);
    sqlite3_bind_int(stmt, 3, rule->port_end);
    sqlite3_bind_int(stmt, 4, rule->protocol);
    sqlite3_bind_int(stmt, 5, rule->action);
    sqlite3_bind_text(stmt, 6, rule->description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, rule->enabled ? 1 : 0);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_get_rule(struct database *db, int id, struct rule_record *rule) {
    if (!db || !db->is_open || !rule) return -1;
    memset(rule, 0, sizeof(*rule));
    db_lock(db);

    const char *sql =
        "SELECT id, ip_address, port_start, port_end, protocol, action, description, enabled, created_at "
        "FROM rules WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rule->id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, rule->ip_address, sizeof(rule->ip_address));
        rule->port_start = (uint16_t)sqlite3_column_int(stmt, 2);
        rule->port_end = (uint16_t)sqlite3_column_int(stmt, 3);
        rule->protocol = (uint8_t)sqlite3_column_int(stmt, 4);
        rule->action = (uint8_t)sqlite3_column_int(stmt, 5);
        safe_col_copy(stmt, 6, rule->description, sizeof(rule->description));
        rule->enabled = sqlite3_column_int(stmt, 7) != 0;
        rule->created_at = sqlite3_column_int64(stmt, 8);
        res = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return res;
}

int database_list_rules(struct database *db, struct rule_record **rules, int *count) {
    if (!db || !db->is_open || !rules || !count) return -1;
    *rules = NULL;
    *count = 0;

    db_lock(db);
    const char *sql =
        "SELECT id, ip_address, port_start, port_end, protocol, action, description, enabled, created_at "
        "FROM rules ORDER BY created_at DESC, id DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    int capacity = 16;
    int size = 0;
    struct rule_record *list = calloc((size_t)capacity, sizeof(struct rule_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (size >= capacity) {
            capacity *= 2;
            struct rule_record *tmp = realloc(list, sizeof(struct rule_record) * (size_t)capacity);
            if (!tmp) {
                free(list);
                sqlite3_finalize(stmt);
                db_unlock(db);
                return -1;
            }
            list = tmp;
        }
        memset(&list[size], 0, sizeof(struct rule_record));
        list[size].id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, list[size].ip_address, sizeof(list[size].ip_address));
        list[size].port_start = (uint16_t)sqlite3_column_int(stmt, 2);
        list[size].port_end = (uint16_t)sqlite3_column_int(stmt, 3);
        list[size].protocol = (uint8_t)sqlite3_column_int(stmt, 4);
        list[size].action = (uint8_t)sqlite3_column_int(stmt, 5);
        safe_col_copy(stmt, 6, list[size].description, sizeof(list[size].description));
        list[size].enabled = sqlite3_column_int(stmt, 7) != 0;
        list[size].created_at = sqlite3_column_int64(stmt, 8);
        size++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *rules = list;
    *count = size;
    return 0;
}

int database_update_rule(struct database *db, int id, const struct rule_record *rule) {
    if (!db || !db->is_open || !rule) return -1;
    db_lock(db);
    const char *sql =
        "UPDATE rules SET ip_address = ?, port_start = ?, port_end = ?, protocol = ?, action = ?, "
        "description = ?, enabled = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, rule->ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, rule->port_start);
    sqlite3_bind_int(stmt, 3, rule->port_end);
    sqlite3_bind_int(stmt, 4, rule->protocol);
    sqlite3_bind_int(stmt, 5, rule->action);
    sqlite3_bind_text(stmt, 6, rule->description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, rule->enabled ? 1 : 0);
    sqlite3_bind_int(stmt, 8, id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_delete_rule(struct database *db, int id) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM rules WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_delete_rule_by_tuple(struct database *db, const char *ip_address, uint16_t port, uint8_t protocol) {
    if (!db || !db->is_open || !ip_address) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM rules WHERE ip_address = ? AND port_start = ? AND protocol = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, port);
    sqlite3_bind_int(stmt, 3, protocol);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE && changes > 0) ? 0 : -1;
}

int database_toggle_rule(struct database *db, int id, bool enabled) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "UPDATE rules SET enabled = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
    sqlite3_bind_int(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// --- IP List Operations ---

int database_insert_ip_list_ex(struct database *db, const struct ip_list_record *entry, int *new_id_out) {
    if (!db || !db->is_open || !entry) return -1;
    db_lock(db);

    // Replace existing matching IP/CIDR/type to prevent duplicate rows
    const char *del_sql = "DELETE FROM ip_lists WHERE ip_address = ? AND cidr_range = ? AND list_type = ?;";
    sqlite3_stmt *del_stmt = NULL;
    if (sqlite3_prepare_v2(db->db, del_sql, -1, &del_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(del_stmt, 1, entry->ip_address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(del_stmt, 2, entry->cidr_range);
        sqlite3_bind_text(del_stmt, 3, entry->list_type, -1, SQLITE_TRANSIENT);
        sqlite3_step(del_stmt);
        sqlite3_finalize(del_stmt);
    }

    const char *sql =
        "INSERT INTO ip_lists (ip_address, cidr_range, list_type, reason, expires_at) "
        "VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->ip_address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, entry->cidr_range);
    sqlite3_bind_text(stmt, 3, entry->list_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)entry->expires_at);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE && new_id_out) {
        *new_id_out = (int)sqlite3_last_insert_rowid(db->db);
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_insert_ip_list(struct database *db, const struct ip_list_record *entry) {
    return database_insert_ip_list_ex(db, entry, NULL);
}

int database_get_ip_list_by_id(struct database *db, int id, struct ip_list_record *entry) {
    if (!db || !db->is_open || !entry) return -1;
    memset(entry, 0, sizeof(*entry));
    db_lock(db);

    const char *sql =
        "SELECT id, ip_address, cidr_range, list_type, reason, COALESCE(expires_at, 0), created_at "
        "FROM ip_lists WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        entry->id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, entry->ip_address, sizeof(entry->ip_address));
        entry->cidr_range = (uint8_t)sqlite3_column_int(stmt, 2);
        safe_col_copy(stmt, 3, entry->list_type, sizeof(entry->list_type));
        safe_col_copy(stmt, 4, entry->reason, sizeof(entry->reason));
        entry->expires_at = (time_t)sqlite3_column_int64(stmt, 5);
        entry->created_at = (time_t)sqlite3_column_int64(stmt, 6);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

int database_delete_ip_list(struct database *db, int id) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM ip_lists WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE && changes > 0) ? 0 : -1;
}

static int database_list_ip_list_by_type(struct database *db, const char *list_type,
                                         struct ip_list_record **entries, int *count) {
    if (!db || !db->is_open || !list_type || !entries || !count) return -1;
    *entries = NULL;
    *count = 0;
    db_lock(db);

    const char *sql =
        "SELECT id, ip_address, cidr_range, list_type, reason, COALESCE(expires_at, 0), created_at "
        "FROM ip_lists WHERE list_type = ? AND (expires_at IS NULL OR expires_at = 0 OR expires_at > ?) "
        "ORDER BY created_at DESC, id DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, list_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time(NULL));

    int capacity = 16;
    int size = 0;
    struct ip_list_record *list = calloc((size_t)capacity, sizeof(struct ip_list_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (size >= capacity) {
            capacity *= 2;
            struct ip_list_record *tmp = realloc(list, sizeof(struct ip_list_record) * (size_t)capacity);
            if (!tmp) {
                free(list);
                sqlite3_finalize(stmt);
                db_unlock(db);
                return -1;
            }
            list = tmp;
        }
        memset(&list[size], 0, sizeof(struct ip_list_record));
        list[size].id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, list[size].ip_address, sizeof(list[size].ip_address));
        list[size].cidr_range = (uint8_t)sqlite3_column_int(stmt, 2);
        safe_col_copy(stmt, 3, list[size].list_type, sizeof(list[size].list_type));
        safe_col_copy(stmt, 4, list[size].reason, sizeof(list[size].reason));
        list[size].expires_at = (time_t)sqlite3_column_int64(stmt, 5);
        list[size].created_at = (time_t)sqlite3_column_int64(stmt, 6);
        size++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *entries = list;
    *count = size;
    return 0;
}

int database_list_whitelist(struct database *db, struct ip_list_record **entries, int *count) {
    return database_list_ip_list_by_type(db, "whitelist", entries, count);
}

int database_list_blacklist(struct database *db, struct ip_list_record **entries, int *count) {
    return database_list_ip_list_by_type(db, "blacklist", entries, count);
}

int database_check_ip_in_list(struct database *db, const char *ip, const char *list_type, bool *found) {
    if (!db || !db->is_open || !ip || !list_type || !found) return -1;
    db_lock(db);
    const char *sql =
        "SELECT id FROM ip_lists WHERE ip_address = ? AND list_type = ? "
        "AND (expires_at IS NULL OR expires_at = 0 OR expires_at > ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, list_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));

    *found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return 0;
}

// --- GeoIP Rule Operations ---

int database_insert_geo_rule(struct database *db, const struct geo_rule_record *rule) {
    if (!db || !db->is_open || !rule) return -1;
    db_lock(db);

    const char *del_sql = "DELETE FROM geo_rules WHERE country_code = ?;";
    sqlite3_stmt *del_stmt = NULL;
    if (sqlite3_prepare_v2(db->db, del_sql, -1, &del_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(del_stmt, 1, rule->country_code, -1, SQLITE_TRANSIENT);
        sqlite3_step(del_stmt);
        sqlite3_finalize(del_stmt);
    }

    const char *sql =
        "INSERT INTO geo_rules (country_code, continent_code, action, priority) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, rule->country_code, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rule->continent_code, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rule->action[0] ? rule->action : "block", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, rule->priority);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_delete_geo_rule(struct database *db, int id) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM geo_rules WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE && changes > 0) ? 0 : -1;
}

int database_delete_geo_rule_by_code(struct database *db, const char *country_code) {
    if (!db || !db->is_open || !country_code) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM geo_rules WHERE UPPER(country_code) = UPPER(?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, country_code, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE && changes > 0) ? 0 : -1;
}

int database_list_geo_rules(struct database *db, struct geo_rule_record **rules, int *count) {
    if (!db || !db->is_open || !rules || !count) return -1;
    *rules = NULL;
    *count = 0;
    db_lock(db);

    const char *sql =
        "SELECT id, country_code, continent_code, action, priority, created_at "
        "FROM geo_rules ORDER BY created_at DESC, id DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    int capacity = 16;
    int size = 0;
    struct geo_rule_record *list = calloc((size_t)capacity, sizeof(struct geo_rule_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (size >= capacity) {
            capacity *= 2;
            struct geo_rule_record *tmp = realloc(list, sizeof(struct geo_rule_record) * (size_t)capacity);
            if (!tmp) {
                free(list);
                sqlite3_finalize(stmt);
                db_unlock(db);
                return -1;
            }
            list = tmp;
        }
        memset(&list[size], 0, sizeof(struct geo_rule_record));
        list[size].id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, list[size].country_code, sizeof(list[size].country_code));
        safe_col_copy(stmt, 2, list[size].continent_code, sizeof(list[size].continent_code));
        safe_col_copy(stmt, 3, list[size].action, sizeof(list[size].action));
        list[size].priority = sqlite3_column_int(stmt, 4);
        list[size].created_at = sqlite3_column_int64(stmt, 5);
        size++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *rules = list;
    *count = size;
    return 0;
}

int database_get_geo_action(struct database *db, const char *country_code, char *action) {
    if (!db || !db->is_open || !country_code || !action) return -1;
    db_lock(db);
    const char *sql = "SELECT action FROM geo_rules WHERE UPPER(country_code) = UPPER(?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, country_code, -1, SQLITE_TRANSIENT);
    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        safe_col_copy(stmt, 0, action, 16);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

// --- Session Operations ---

int database_insert_session(struct database *db, const struct session_record *session) {
    if (!db || !db->is_open || !session) return -1;
    db_lock(db);
    const char *sql = "INSERT INTO sessions (user_id, session_id, token, expires_at) VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, session->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session->session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session->token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)session->expires_at);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_get_session(struct database *db, const char *token, struct session_record *session) {
    if (!db || !db->is_open || !token || !session) return -1;
    memset(session, 0, sizeof(*session));
    db_lock(db);

    const char *sql = "SELECT id, user_id, session_id, token, expires_at, created_at FROM sessions WHERE token = ? AND expires_at > ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time(NULL));

    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        session->id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, session->user_id, sizeof(session->user_id));
        safe_col_copy(stmt, 2, session->session_id, sizeof(session->session_id));
        safe_col_copy(stmt, 3, session->token, sizeof(session->token));
        session->expires_at = (time_t)sqlite3_column_int64(stmt, 4);
        session->created_at = (time_t)sqlite3_column_int64(stmt, 5);
        res = 0;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    return res;
}

int database_delete_session(struct database *db, const char *token) {
    if (!db || !db->is_open || !token) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM sessions WHERE token = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_delete_expired_sessions(struct database *db) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM sessions WHERE expires_at <= ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// --- Analytics & Config Operations ---

int database_insert_analytics_hourly(struct database *db, const struct analytics_hourly *analytics) {
    if (!db || !db->is_open || !analytics) return -1;
    db_lock(db);
    const char *sql =
        "INSERT OR REPLACE INTO analytics_hourly "
        "(timestamp, total_packets, total_bytes, attack_count, unique_sources, top_attacker, top_protocol) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)analytics->timestamp);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)analytics->total_packets);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)analytics->total_bytes);
    sqlite3_bind_int(stmt, 4, analytics->attack_count);
    sqlite3_bind_int(stmt, 5, analytics->unique_sources);
    sqlite3_bind_text(stmt, 6, analytics->top_attacker, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, analytics->top_protocol, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_get_analytics_summary(struct database *db, time_t from, time_t to,
                                   struct analytics_hourly *summary) {
    if (!db || !db->is_open || !summary) return -1;
    memset(summary, 0, sizeof(*summary));
    db_lock(db);
    const char *sql =
        "SELECT COALESCE(SUM(total_packets), 0), COALESCE(SUM(total_bytes), 0), "
        "COALESCE(SUM(attack_count), 0), COALESCE(MAX(unique_sources), 0) "
        "FROM analytics_hourly WHERE timestamp >= ? AND timestamp <= ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)from);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(to > 0 ? to : time(NULL)));

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        summary->timestamp = from;
        summary->total_packets = (uint64_t)sqlite3_column_int64(stmt, 0);
        summary->total_bytes = (uint64_t)sqlite3_column_int64(stmt, 1);
        summary->attack_count = sqlite3_column_int(stmt, 2);
        summary->unique_sources = sqlite3_column_int(stmt, 3);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

int database_set_config(struct database *db, const char *key, const char *value) {
    if (!db || !db->is_open || !key || !value) return -1;
    db_lock(db);
    const char *sql =
        "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_get_config(struct database *db, const char *key, char *value, size_t value_len) {
    if (!db || !db->is_open || !key || !value || value_len == 0) return -1;
    value[0] = '\0';
    db_lock(db);
    const char *sql = "SELECT value FROM config WHERE key = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        safe_col_copy(stmt, 0, value, value_len);
        rc = 0;
    }
    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

// --- API Key Operations ---

int database_create_api_key(struct database *db, const struct api_key_record *key) {
    if (!db || !db->is_open || !key) return -1;
    db_lock(db);
    const char *sql = "INSERT INTO api_keys (name, key_hash, key_prefix, permissions, expires_at) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key->key_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, key->key_prefix, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, key->permissions, -1, SQLITE_TRANSIENT);
    if (key->expires_at > 0)
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)key->expires_at);
    else
        sqlite3_bind_null(stmt, 5);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_list_api_keys(struct database *db, struct api_key_record **keys, int *count) {
    if (!db || !db->is_open || !keys || !count) return -1;
    *keys = NULL;
    *count = 0;
    db_lock(db);

    const char *sql = "SELECT id, name, key_hash, key_prefix, permissions, COALESCE(last_used_at, 0), COALESCE(expires_at, 0), created_at FROM api_keys ORDER BY created_at DESC, id DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    int capacity = 10;
    int size = 0;
    struct api_key_record *list = calloc((size_t)capacity, sizeof(struct api_key_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (size >= capacity) {
            capacity *= 2;
            struct api_key_record *tmp = realloc(list, sizeof(struct api_key_record) * (size_t)capacity);
            if (!tmp) {
                free(list);
                sqlite3_finalize(stmt);
                db_unlock(db);
                return -1;
            }
            list = tmp;
        }
        memset(&list[size], 0, sizeof(struct api_key_record));
        list[size].id = sqlite3_column_int(stmt, 0);
        safe_col_copy(stmt, 1, list[size].name, sizeof(list[size].name));
        safe_col_copy(stmt, 2, list[size].key_hash, sizeof(list[size].key_hash));
        safe_col_copy(stmt, 3, list[size].key_prefix, sizeof(list[size].key_prefix));
        safe_col_copy(stmt, 4, list[size].permissions, sizeof(list[size].permissions));
        list[size].last_used_at = (time_t)sqlite3_column_int64(stmt, 5);
        list[size].expires_at = (time_t)sqlite3_column_int64(stmt, 6);
        list[size].created_at = (time_t)sqlite3_column_int64(stmt, 7);
        size++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *keys = list;
    *count = size;
    return 0;
}

int database_delete_api_key(struct database *db, int id) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "DELETE FROM api_keys WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_validate_api_key(struct database *db, const char *key_hash, struct api_key_record *key_details) {
    if (!db || !db->is_open || !key_hash) return -1;
    db_lock(db);
    const char *sql = "SELECT id, name, permissions FROM api_keys WHERE key_hash = ? AND (expires_at IS NULL OR expires_at = 0 OR expires_at > ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time(NULL));

    int res = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (key_details) {
            memset(key_details, 0, sizeof(*key_details));
            key_details->id = sqlite3_column_int(stmt, 0);
            safe_col_copy(stmt, 1, key_details->name, sizeof(key_details->name));
            safe_col_copy(stmt, 2, key_details->permissions, sizeof(key_details->permissions));
        }
        res = 0;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    return res;
}

int database_update_api_key_last_used(struct database *db, int id) {
    if (!db || !db->is_open) return -1;
    db_lock(db);
    const char *sql = "UPDATE api_keys SET last_used_at = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int(stmt, 2, id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// --- Security Event Operations (Tetragon Integration) ---

int db_insert_security_event_ex(int64_t timestamp, const char *event_type, int severity,
                                const char *process_name, int pid, int ppid, int uid,
                                const char *command, const char *binary_path,
                                const char *parent_binary, const char *action,
                                const char *policy_name, const char *src_ip,
                                const char *dst_ip, int dst_port, const char *file_path,
                                const char *file_operation, const char *metadata,
                                int64_t *new_id_out) {
    if (new_id_out) *new_id_out = 0;
    if (!g_db || !g_db->is_open) return -1;
    db_lock(g_db);

    const char *sql =
        "INSERT INTO security_events ("
        "timestamp, event_type, severity, process_name, pid, ppid, uid, "
        "command, binary_path, parent_binary, action, policy_name, "
        "src_ip, dst_ip, dst_port, file_path, file_operation, metadata"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(g_db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, (event_type && event_type[0]) ? event_type : "unknown", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, severity);
    sqlite3_bind_text(stmt, 4, process_name ? process_name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, pid);
    sqlite3_bind_int(stmt, 6, ppid);
    sqlite3_bind_int(stmt, 7, uid);
    sqlite3_bind_text(stmt, 8, command ? command : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, binary_path ? binary_path : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, parent_binary ? parent_binary : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, action ? action : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, policy_name ? policy_name : "", -1, SQLITE_TRANSIENT);

    if (src_ip && src_ip[0]) sqlite3_bind_text(stmt, 13, src_ip, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 13);

    if (dst_ip && dst_ip[0]) sqlite3_bind_text(stmt, 14, dst_ip, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 14);

    if (dst_port > 0) sqlite3_bind_int(stmt, 15, dst_port);
    else sqlite3_bind_null(stmt, 15);

    if (file_path && file_path[0]) sqlite3_bind_text(stmt, 16, file_path, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 16);

    if (file_operation && file_operation[0]) sqlite3_bind_text(stmt, 17, file_operation, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 17);

    if (metadata && metadata[0]) sqlite3_bind_text(stmt, 18, metadata, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 18);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE && new_id_out) {
        *new_id_out = (int64_t)sqlite3_last_insert_rowid(g_db->db);
    }
    sqlite3_finalize(stmt);
    db_unlock(g_db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_insert_security_event(int64_t timestamp, const char *event_type, int severity,
                             const char *process_name, int pid, int ppid, int uid,
                             const char *command, const char *binary_path,
                             const char *parent_binary, const char *action,
                             const char *policy_name, const char *src_ip,
                             const char *dst_ip, int dst_port, const char *file_path,
                             const char *file_operation, const char *metadata) {
    return db_insert_security_event_ex(timestamp, event_type, severity, process_name,
                                       pid, ppid, uid, command, binary_path, parent_binary,
                                       action, policy_name, src_ip, dst_ip, dst_port,
                                       file_path, file_operation, metadata, NULL);
}

int database_list_security_events(struct database *db, struct security_event_record **events,
                                  int *count, int severity_min, const char *event_type,
                                  time_t from, time_t to, int limit, int offset) {
    if (!db || !db->is_open || !events || !count) return -1;
    *events = NULL;
    *count = 0;

    if (limit <= 0) limit = 100;
    if (limit > 10000) limit = 10000;
    if (offset < 0) offset = 0;

    char sql[1024];
    strcpy(sql, "SELECT id, timestamp, event_type, severity, process_name, pid, ppid, uid, "
                "command, binary_path, parent_binary, action, policy_name, src_ip, dst_ip, "
                "dst_port, file_path, file_operation, metadata, created_at "
                "FROM security_events WHERE 1=1");

    if (severity_min > 0) strcat(sql, " AND severity >= ?");
    if (event_type && event_type[0]) strcat(sql, " AND event_type = ?");
    if (from > 0) strcat(sql, " AND timestamp >= ?");
    if (to > 0) strcat(sql, " AND timestamp <= ?");
    strcat(sql, " ORDER BY timestamp DESC LIMIT ? OFFSET ?;");

    db_lock(db);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    int bind_idx = 1;
    if (severity_min > 0) sqlite3_bind_int(stmt, bind_idx++, severity_min);
    if (event_type && event_type[0]) sqlite3_bind_text(stmt, bind_idx++, event_type, -1, SQLITE_TRANSIENT);
    if (from > 0) sqlite3_bind_int64(stmt, bind_idx++, (sqlite3_int64)from);
    if (to > 0) sqlite3_bind_int64(stmt, bind_idx++, (sqlite3_int64)to);
    sqlite3_bind_int(stmt, bind_idx++, limit);
    sqlite3_bind_int(stmt, bind_idx++, offset);

    struct security_event_record *list = calloc((size_t)limit, sizeof(struct security_event_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        list[idx].id = sqlite3_column_int64(stmt, 0);
        list[idx].timestamp = sqlite3_column_int64(stmt, 1);
        safe_col_copy(stmt, 2, list[idx].event_type, sizeof(list[idx].event_type));
        list[idx].severity = sqlite3_column_int(stmt, 3);
        safe_col_copy(stmt, 4, list[idx].process_name, sizeof(list[idx].process_name));
        list[idx].pid = sqlite3_column_int(stmt, 5);
        list[idx].ppid = sqlite3_column_int(stmt, 6);
        list[idx].uid = sqlite3_column_int(stmt, 7);
        safe_col_copy(stmt, 8, list[idx].command, sizeof(list[idx].command));
        safe_col_copy(stmt, 9, list[idx].binary_path, sizeof(list[idx].binary_path));
        safe_col_copy(stmt, 10, list[idx].parent_binary, sizeof(list[idx].parent_binary));
        safe_col_copy(stmt, 11, list[idx].action, sizeof(list[idx].action));
        safe_col_copy(stmt, 12, list[idx].policy_name, sizeof(list[idx].policy_name));
        safe_col_copy(stmt, 13, list[idx].src_ip, sizeof(list[idx].src_ip));
        safe_col_copy(stmt, 14, list[idx].dst_ip, sizeof(list[idx].dst_ip));
        list[idx].dst_port = sqlite3_column_int(stmt, 15);
        safe_col_copy(stmt, 16, list[idx].file_path, sizeof(list[idx].file_path));
        safe_col_copy(stmt, 17, list[idx].file_operation, sizeof(list[idx].file_operation));
        safe_col_copy(stmt, 18, list[idx].metadata, sizeof(list[idx].metadata));
        list[idx].created_at = sqlite3_column_int64(stmt, 19);
        idx++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *events = list;
    *count = idx;
    return 0;
}

int database_get_security_stats(struct database *db, time_t from, time_t to,
                                int *total_events, int *critical_alerts,
                                int *events_blocked) {
    if (!db || !db->is_open) return -1;
    db_lock(db);

    const char *sql =
        "SELECT "
        "COUNT(*) as total, "
        "COALESCE(SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END), 0) as critical, "
        "COALESCE(SUM(CASE WHEN action IN ('Sigkill', 'KPROBE_ACTION_SIGKILL', 'block') THEN 1 ELSE 0 END), 0) as blocked "
        "FROM security_events "
        "WHERE timestamp >= ? AND timestamp <= ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)from);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)to);

    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (total_events) *total_events = sqlite3_column_int(stmt, 0);
        if (critical_alerts) *critical_alerts = sqlite3_column_int(stmt, 1);
        if (events_blocked) *events_blocked = sqlite3_column_int(stmt, 2);
        rc = 0;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    return rc;
}

int database_delete_old_security_events(struct database *db, time_t older_than) {
    if (!db || !db->is_open) return -1;
    db_lock(db);

    const char *sql = "DELETE FROM security_events WHERE timestamp < ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)older_than);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_insert_attack_correlation(struct database *db,
                                       const struct attack_correlation_record *corr) {
    if (!db || !db->is_open || !corr) return -1;
    db_lock(db);

    const char *sql =
        "INSERT INTO attack_correlation ("
        "timestamp, attack_type, confidence_score, network_event_id, "
        "security_event_id, description, source_ip, details"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
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
    db_unlock(db);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int database_has_recent_correlation(struct database *db, const char *src_ip,
                                    const char *attack_type, time_t cutoff_ts) {
    if (!db || !db->is_open || !attack_type || !attack_type[0]) return 0;
    db_lock(db);

    const char *sql =
        "SELECT id FROM attack_correlation "
        "WHERE source_ip = ? AND attack_type = ? AND timestamp >= ? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, src_ip ? src_ip : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, attack_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)cutoff_ts);

    int found = (sqlite3_step(stmt) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(stmt);
    db_unlock(db);
    return found;
}

int database_list_attack_correlations(struct database *db,
                                      struct attack_correlation_record **corrs,
                                      int *count, float min_confidence,
                                      time_t from, time_t to, int limit) {
    if (!db || !db->is_open || !corrs || !count) return -1;
    *corrs = NULL;
    *count = 0;

    if (limit <= 0) limit = 100;
    if (limit > 10000) limit = 10000;

    db_lock(db);
    const char *sql =
        "SELECT id, timestamp, attack_type, confidence_score, network_event_id, "
        "security_event_id, description, source_ip, details, created_at "
        "FROM attack_correlation "
        "WHERE confidence_score >= ? AND timestamp >= ? AND timestamp <= ? "
        "ORDER BY timestamp DESC LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock(db);
        return -1;
    }

    sqlite3_bind_double(stmt, 1, min_confidence);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)from);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)to);
    sqlite3_bind_int(stmt, 4, limit);

    struct attack_correlation_record *list = calloc((size_t)limit, sizeof(struct attack_correlation_record));
    if (!list) {
        sqlite3_finalize(stmt);
        db_unlock(db);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < limit) {
        list[idx].id = sqlite3_column_int64(stmt, 0);
        list[idx].timestamp = sqlite3_column_int64(stmt, 1);
        safe_col_copy(stmt, 2, list[idx].attack_type, sizeof(list[idx].attack_type));
        list[idx].confidence_score = (float)sqlite3_column_double(stmt, 3);
        list[idx].network_event_id = sqlite3_column_int64(stmt, 4);
        list[idx].security_event_id = sqlite3_column_int64(stmt, 5);
        safe_col_copy(stmt, 6, list[idx].description, sizeof(list[idx].description));
        safe_col_copy(stmt, 7, list[idx].source_ip, sizeof(list[idx].source_ip));
        safe_col_copy(stmt, 8, list[idx].details, sizeof(list[idx].details));
        list[idx].created_at = sqlite3_column_int64(stmt, 9);
        idx++;
    }

    sqlite3_finalize(stmt);
    db_unlock(db);
    *corrs = list;
    *count = idx;
    return 0;
}

// --- Cleanup Helpers ---

void database_free_api_key_list(struct api_key_record *keys, int count) {
    (void)count;
    if (keys) free(keys);
}

void database_free_attack_list(struct attack_record *attacks, int count) {
    (void)count;
    if (attacks) free(attacks);
}

void database_free_traffic_list(struct traffic_record *traffic, int count) {
    (void)count;
    if (traffic) free(traffic);
}

void database_free_rule_list(struct rule_record *rules, int count) {
    (void)count;
    if (rules) free(rules);
}

void database_free_ip_list(struct ip_list_record *entries, int count) {
    (void)count;
    if (entries) free(entries);
}

void database_free_geo_rule_list(struct geo_rule_record *rules, int count) {
    (void)count;
    if (rules) free(rules);
}

void database_free_security_event_list(struct security_event_record *events, int count) {
    (void)count;
    if (events) free(events);
}

void database_free_correlation_list(struct attack_correlation_record *corrs, int count) {
    (void)count;
    if (corrs) free(corrs);
}

// --- Private Helpers ---

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
