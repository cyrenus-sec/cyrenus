#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>
#include "../../include/api_handlers.h"
#include "../../include/database.h"

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
