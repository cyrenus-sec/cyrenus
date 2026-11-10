#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>
#include "../../include/api_handlers.h"
#include "../../include/attack_info.h"
#include "../../include/database.h"

#define AUTH_MAX_FAILED_LOGINS 5
#define AUTH_WINDOW_SEC        60
#define AUTH_LOCKOUT_SEC       300
#define AUTH_LIMITER_SLOTS     512

struct login_attempt_entry {
    char ip[64];
    time_t window_start;
    time_t last_attempt;
    time_t locked_until;
    int fail_count;
};

static struct login_attempt_entry g_login_attempts[AUTH_LIMITER_SLOTS];
static pthread_mutex_t g_auth_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

static int parse_and_format_ip_token(const char *raw, char *out, size_t out_len) {
    if (!raw || !out || out_len == 0) return -1;
    while (*raw && isspace((unsigned char)*raw)) raw++;
    char buf[64];
    size_t i = 0;
    while (raw[i] && !isspace((unsigned char)raw[i]) && raw[i] != ',' && i + 1 < sizeof(buf)) {
        buf[i] = raw[i];
        i++;
    }
    buf[i] = '\0';
    if (buf[0] == '\0') return -1;

    struct cyrenus_ip parsed;
    if (cyrenus_str_to_ip(buf, &parsed, NULL) != 0) {
        return -1;
    }
    cyrenus_ip_to_str(&parsed, out, out_len);
    return 0;
}

static int peer_is_trusted_proxy(const char *peer_ip, const struct runtime_config *cfg) {
    if (!peer_ip || !cfg || cfg->trusted_proxy[0] == '\0') {
        return 0;
    }

    struct cyrenus_ip peer_parsed, proxy_parsed;
    if (cyrenus_str_to_ip(peer_ip, &peer_parsed, NULL) != 0) {
        return 0;
    }

    // Match comma-separated trusted_proxy list (or loopback alias)
    const char *p = cfg->trusted_proxy;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == '\0') break;
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t') p++;
        size_t len = (size_t)(p - start);
        if (len > 0 && len < 64) {
            char tok[64];
            memcpy(tok, start, len);
            tok[len] = '\0';
            if (strcasecmp(tok, "loopback") == 0) {
                if (strcmp(peer_ip, "127.0.0.1") == 0 || strcmp(peer_ip, "::1") == 0) {
                    return 1;
                }
            } else if (cyrenus_str_to_ip(tok, &proxy_parsed, NULL) == 0 &&
                       cyrenus_ip_equals(&peer_parsed, &proxy_parsed)) {
                return 1;
            }
        }
    }
    return 0;
}

static void extract_client_ip(struct MHD_Connection *connection,
                              const struct api_context *ctx,
                              char ip_out[64]) {
    snprintf(ip_out, 64, "unknown");
    if (!connection) return;

    char peer_ip[64] = {0};
    const union MHD_ConnectionInfo *ci = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci && ci->client_addr) {
        if (ci->client_addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)ci->client_addr;
            struct cyrenus_ip ip;
            cyrenus_ip_from_v4(&ip, sin->sin_addr.s_addr);
            cyrenus_ip_to_str(&ip, peer_ip, sizeof(peer_ip));
        } else if (ci->client_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ci->client_addr;
            struct cyrenus_ip ip;
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
                uint32_t v4_be = 0;
                memcpy(&v4_be, sin6->sin6_addr.s6_addr + 12, 4);
                cyrenus_ip_from_v4(&ip, v4_be);
            } else {
                cyrenus_ip_from_v6(&ip, &sin6->sin6_addr);
            }
            cyrenus_ip_to_str(&ip, peer_ip, sizeof(peer_ip));
        }
    }

    if (peer_ip[0] != '\0') {
        snprintf(ip_out, 64, "%s", peer_ip);
    }

    if (ctx && peer_is_trusted_proxy(peer_ip, ctx->config)) {
        const char *xff = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Forwarded-For");
        if (xff && parse_and_format_ip_token(xff, ip_out, 64) == 0) {
            return;
        }
        const char *xri = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Real-IP");
        if (xri && parse_and_format_ip_token(xri, ip_out, 64) == 0) {
            return;
        }
    }
}

static struct login_attempt_entry *find_or_alloc_slot(const char *ip, time_t now) {
    struct login_attempt_entry *empty_slot = NULL;
    struct login_attempt_entry *oldest_slot = &g_login_attempts[0];

    for (int i = 0; i < AUTH_LIMITER_SLOTS; i++) {
        struct login_attempt_entry *e = &g_login_attempts[i];
        if (e->ip[0] != '\0' && strcmp(e->ip, ip) == 0) {
            return e;
        }
        if (e->ip[0] == '\0' && !empty_slot) {
            empty_slot = e;
        }
        if (e->last_attempt < oldest_slot->last_attempt) {
            oldest_slot = e;
        }
    }

    struct login_attempt_entry *slot = empty_slot ? empty_slot : oldest_slot;
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->ip, sizeof(slot->ip), "%s", ip);
    slot->window_start = now;
    slot->last_attempt = now;
    return slot;
}

static int check_login_lockout(const char *ip, int *retry_after_out) {
    time_t now = time(NULL);
    int locked = 0;
    int retry = 0;

    pthread_mutex_lock(&g_auth_limit_mutex);
    for (int i = 0; i < AUTH_LIMITER_SLOTS; i++) {
        if (g_login_attempts[i].ip[0] != '\0' && strcmp(g_login_attempts[i].ip, ip) == 0) {
            if (g_login_attempts[i].locked_until > now) {
                locked = 1;
                retry = (int)(g_login_attempts[i].locked_until - now);
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_auth_limit_mutex);

    if (retry_after_out) *retry_after_out = retry;
    return locked;
}

static void record_login_result(const char *ip, int success) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_auth_limit_mutex);
    if (success) {
        for (int i = 0; i < AUTH_LIMITER_SLOTS; i++) {
            if (g_login_attempts[i].ip[0] != '\0' && strcmp(g_login_attempts[i].ip, ip) == 0) {
                memset(&g_login_attempts[i], 0, sizeof(g_login_attempts[i]));
                break;
            }
        }
    } else {
        struct login_attempt_entry *slot = find_or_alloc_slot(ip, now);
        if (now - slot->window_start > AUTH_WINDOW_SEC) {
            slot->window_start = now;
            slot->fail_count = 1;
            slot->locked_until = 0;
        } else {
            slot->fail_count++;
            if (slot->fail_count >= AUTH_MAX_FAILED_LOGINS) {
                slot->locked_until = now + AUTH_LOCKOUT_SEC;
            }
        }
        slot->last_attempt = now;
    }
    pthread_mutex_unlock(&g_auth_limit_mutex);
}

// Constant-time string equality check via SHA-256 + CRYPTO_memcmp (avoids timing & length leaks)
static int secure_str_equals(const char *a, const char *b) {
    if (!a || !b) return 0;
    unsigned char hash_a[EVP_MAX_MD_SIZE];
    unsigned char hash_b[EVP_MAX_MD_SIZE];
    unsigned int len_a = 0, len_b = 0;

    if (!EVP_Digest(a, strlen(a), hash_a, &len_a, EVP_sha256(), NULL)) return 0;
    if (!EVP_Digest(b, strlen(b), hash_b, &len_b, EVP_sha256(), NULL)) return 0;
    if (len_a != len_b) return 0;
    return CRYPTO_memcmp(hash_a, hash_b, len_a) == 0;
}

// Helper: Create a new session
static char *create_session(struct database *db, const char *username) {
    if (!db || !db->is_open || !username) return NULL;
    struct session_record session = {0};

    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, session.user_id);

    uuid_generate(uuid);
    uuid_unparse(uuid, session.session_id);

    time_t now = time(NULL);
    session.expires_at = now + 3600; // 1 hour expiry

    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return NULL;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return NULL;

    char meta[192];
    snprintf(meta, sizeof(meta), "%s|%s|%lld", username, session.session_id, (long long)now);

    int ok = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(mdctx, random_bytes, sizeof(random_bytes)) == 1 &&
             EVP_DigestUpdate(mdctx, meta, strlen(meta)) == 1 &&
             EVP_DigestFinal_ex(mdctx, hash, &hash_len) == 1;
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));

    if (!ok || hash_len != SHA256_DIGEST_LENGTH) {
        return NULL;
    }

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(session.token + (i * 2), "%02x", hash[i]);
    }
    session.token[64] = '\0';

    if (database_insert_session(db, &session) != 0) {
        return NULL;
    }

    return strdup(session.token);
}

// Handler: POST /api/v1/auth/login
enum MHD_Result api_auth_login(struct MHD_Connection *connection,
                               struct api_context *ctx,
                               const char *upload_data, size_t size) {
    char client_ip[64];
    extract_client_ip(connection, ctx, client_ip);

    int retry_after = 0;
    if (check_login_lockout(client_ip, &retry_after)) {
        return api_send_rate_limited(
            connection,
            retry_after,
            "Too many failed login attempts. Account/IP temporarily locked."
        );
    }

    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    json_object *j_username = NULL, *j_password = NULL;
    if (!json_object_object_get_ex(root, "username", &j_username) ||
        !json_object_object_get_ex(root, "password", &j_password)) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing credentials");
    }

    const char *username = json_object_get_string(j_username);
    const char *password = json_object_get_string(j_password);

    enum MHD_Result ret;
    if (username && password && ctx && ctx->config &&
        secure_str_equals(username, ctx->config->username) &&
        secure_str_equals(password, ctx->config->password)) {

        record_login_result(client_ip, 1);

        char *token = create_session(ctx->db, username);
        if (token) {
            json_object *resp_obj = json_object_new_object();
            json_object_object_add(resp_obj, "token", json_object_new_string(token));
            json_object_object_add(resp_obj, "expires_in", json_object_new_int(3600));
            json_object_object_add(resp_obj, "username", json_object_new_string(username));

            const char *json_str = json_object_to_json_string(resp_obj);
            ret = api_send_json(connection, MHD_HTTP_OK, json_str);

            free(token);
            json_object_put(resp_obj);
        } else {
            ret = api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Session creation failed");
        }
    } else {
        record_login_result(client_ip, 0);
        ret = api_send_error(connection, MHD_HTTP_UNAUTHORIZED, "Invalid credentials");
    }

    json_object_put(root);
    return ret;
}

// Handler: GET /api/v1/auth/verify
enum MHD_Result api_auth_verify(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *token) {
    if (!token) {
        return api_send_json(connection, MHD_HTTP_UNAUTHORIZED, "{\"valid\":false}");
    }

    if (strncmp(token, "Bearer ", 7) == 0) {
        token += 7;
    }

    struct session_record session;
    if (ctx && ctx->db && database_get_session(ctx->db, token, &session) == 0) {
        if (time(NULL) < session.expires_at) {
            return api_send_json(connection, MHD_HTTP_OK, "{\"valid\":true}");
        }
    }

    return api_send_json(connection, MHD_HTTP_UNAUTHORIZED, "{\"valid\":false}");
}

// Handler: POST /api/v1/auth/logout
enum MHD_Result api_auth_logout(struct MHD_Connection *connection,
                                struct api_context *ctx,
                                const char *token) {
    if (token && ctx && ctx->db) {
        if (strncmp(token, "Bearer ", 7) == 0) {
            token += 7;
        }
        database_delete_session(ctx->db, token);
    }

    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"logged out\"}");
}
