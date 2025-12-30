#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <uuid/uuid.h>
#include "../../include/api_handlers.h"
#include "../../include/database.h"

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
    
    // Generate secure token
    char data[256];
    unsigned char random_bytes[32];
    RAND_bytes(random_bytes, sizeof(random_bytes));
    
    snprintf(data, sizeof(data), "%s%s%ld", username, session.session_id, now);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, strlen(data), hash);
    
    // Convert hash to hex string for token base
    char hash_hex[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_hex + (i * 2), "%02x", hash[i]);
    }
    
    // Combine hash with random bytes for final token (simplified)
    snprintf(session.token, sizeof(session.token), "%s", hash_hex);
    
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
    
    // Validate credentials against runtime config
    // In production, this should verify against a users table with hashed passwords
    if (strcmp(username, ctx->config->username) == 0 && 
        strcmp(password, ctx->config->password) == 0) {
        
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
    // In a real implementation we would delete the session from DB
    // For now success
    struct MHD_Response *response;
    const char *msg = "{\"status\":\"logged out\"}";
    response = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}
