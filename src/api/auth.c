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
static char* create_session(struct database *db, const char* username) {
    struct session_record session = {0};
    
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, session.user_id); // In a real app we'd lookup user ID
    
    uuid_generate(uuid);
    uuid_unparse(uuid, session.session_id);
    
    time_t now = time(NULL);
    session.expires_at = now + 3600; // 1 hour expiry
    
    // Generate secure token mixing CSPRNG random_bytes + context metadata
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
    
    struct MHD_Response *response;
    enum MHD_Result ret;

    if (!upload_data || size == 0) {
        const char *err = "{\"error\":\"Missing request body\"}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        const char *err = "{\"error\":\"Invalid JSON\"}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    json_object *j_username, *j_password;
    if (!json_object_object_get_ex(root, "username", &j_username) ||
        !json_object_object_get_ex(root, "password", &j_password)) {
        json_object_put(root);
        const char *err = "{\"error\":\"Missing credentials\"}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    const char *username = json_object_get_string(j_username);
    const char *password = json_object_get_string(j_password);
    
    // Validate credentials in constant time against runtime config
    if (username && password && ctx && ctx->config &&
        secure_str_equals(username, ctx->config->username) &&
        secure_str_equals(password, ctx->config->password)) {
        
        char *token = create_session(ctx->db, username);
        if (token) {
            json_object *resp_obj = json_object_new_object();
            json_object_object_add(resp_obj, "token", json_object_new_string(token));
            json_object_object_add(resp_obj, "expires_in", json_object_new_int(3600));
            
            const char *json_str = json_object_to_json_string(resp_obj);
            response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            
            free(token);
            json_object_put(resp_obj);
        } else {
            const char *err = "{\"error\":\"Session creation failed\"}";
            response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        }
    } else {
        const char *err = "{\"error\":\"Invalid credentials\"}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);
    }
    
    json_object_put(root);
    MHD_destroy_response(response);
    return ret;
}

// Handler: GET /api/v1/auth/verify
enum MHD_Result api_auth_verify(struct MHD_Connection *connection, 
                                struct api_context *ctx,
                                const char *token) {
    struct MHD_Response *response;
    enum MHD_Result ret;
    
    if (!token) {
        const char *err = "{\"valid\":false}";
        response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    // Skip "Bearer " prefix if present
    if (strncmp(token, "Bearer ", 7) == 0) {
        token += 7;
    }
    
    struct session_record session;
    if (database_get_session(ctx->db, token, &session) == 0) {
        // Check expiry
        if (time(NULL) < session.expires_at) {
            const char *succ = "{\"valid\":true}";
            response = MHD_create_response_from_buffer(strlen(succ), (void*)succ, MHD_RESPMEM_MUST_COPY);
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            return ret;
        }
    }
    
    const char *err = "{\"valid\":false}";
    response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);
    MHD_destroy_response(response);
    return ret;
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

    struct MHD_Response *response;
    const char *msg = "{\"status\":\"logged out\"}";
    response = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}
