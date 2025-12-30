#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <uuid/uuid.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <microhttpd.h>
#include "../../include/api_handlers.h"
#include "../../include/database.h"
#include "../../include/common.h"

// Helper to generate a secure random key
// Format: cyr_k_<random_32_chars>
static void generate_api_key(char *key_buffer, size_t buffer_size) {
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_len = strlen(charset);
    
    snprintf(key_buffer, buffer_size, "cyr_k_");
    size_t prefix_len = 6;
    
    for (size_t i = prefix_len; i < buffer_size - 1; i++) {
        key_buffer[i] = charset[rand() % charset_len];
    }
    key_buffer[buffer_size - 1] = '\0';
}

void hash_api_key(const char *key, char *hash_out) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        // Handle error, for now just zero out or return
         hash_out[0] = '\0';
         return;
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
         EVP_MD_CTX_free(mdctx);
         return;
    }

    if(1 != EVP_DigestUpdate(mdctx, key, strlen(key))) {
         EVP_MD_CTX_free(mdctx);
         return;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
         EVP_MD_CTX_free(mdctx);
         return;
    }

    EVP_MD_CTX_free(mdctx);
    
    for(unsigned int i = 0; i < hash_len; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[64] = '\0';
}

// GET /api/v1/keys
enum MHD_Result api_keys_list(struct MHD_Connection *connection, struct api_context *ctx) {
    struct api_key_record *keys = NULL;
    int count = 0;
    
    if (database_list_api_keys(ctx->db, &keys, &count) != 0) {
        const char *err = "{\"error\":\"Database error\"}";
         struct MHD_Response *response = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_MUST_COPY);
        return MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
    }
    
    struct json_object *j_array = json_object_new_array();
    for (int i = 0; i < count; i++) {
        struct json_object *j_key = json_object_new_object();
        json_object_object_add(j_key, "id", json_object_new_int(keys[i].id));
        json_object_object_add(j_key, "name", json_object_new_string(keys[i].name));
        json_object_object_add(j_key, "prefix", json_object_new_string(keys[i].key_prefix));
        json_object_object_add(j_key, "permissions", json_object_new_string(keys[i].permissions));
        json_object_object_add(j_key, "last_used_at", json_object_new_int64(keys[i].last_used_at));
        json_object_object_add(j_key, "expires_at", json_object_new_int64(keys[i].expires_at));
        json_object_object_add(j_key, "created_at", json_object_new_int64(keys[i].created_at));
        json_object_array_add(j_array, j_key);
    }
    
    database_free_api_key_list(keys, count);
    
    const char *json_str = json_object_to_json_string(j_array);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(j_array);
    return ret;
}

// POST /api/v1/keys
enum MHD_Result api_keys_create(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size) {
    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT));
    }
    
    struct json_object *j_name, *j_perms, *j_expires;
    const char *name = "API Key";
    const char *perms = "read,write";
    time_t expires_at = 0; // Never
    
    if (json_object_object_get_ex(root, "name", &j_name)) name = json_object_get_string(j_name);
    if (json_object_object_get_ex(root, "permissions", &j_perms)) perms = json_object_get_string(j_perms);
    if (json_object_object_get_ex(root, "expires_in_days", &j_expires)) {
        int days = json_object_get_int(j_expires);
        if (days > 0) expires_at = time(NULL) + (days * 86400);
    }
    
    // Generate Key
    char raw_key[64];
    generate_api_key(raw_key, sizeof(raw_key));
    
    char key_hash[65];
    hash_api_key(raw_key, key_hash);
    
    struct api_key_record key_record = {0};
    strncpy(key_record.name, name, sizeof(key_record.name)-1);
    strncpy(key_record.key_hash, key_hash, sizeof(key_record.key_hash)-1);
    
    // Prefix: cyr_k_XXXX (first 10 chars)
    strncpy(key_record.key_prefix, raw_key, 10); 
    key_record.key_prefix[10] = '\0';
    
    strncpy(key_record.permissions, perms, sizeof(key_record.permissions)-1);
    key_record.expires_at = expires_at;
    
    if (database_create_api_key(ctx->db, &key_record) != 0) {
        json_object_put(root);
        return MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT));
    }
    
    // Return the RAW key (only time user sees it)
    struct json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "api_key", json_object_new_string(raw_key));
    json_object_object_add(j_resp, "message", json_object_new_string("Save this key securely. It will not be shown again."));
    
    const char *json_str = json_object_to_json_string(j_resp);
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(root);
    json_object_put(j_resp);
    return ret;
}

// DELETE /api/v1/keys
enum MHD_Result api_keys_delete(struct MHD_Connection *connection, struct api_context *ctx, const char *upload_data, size_t size) {
    // Expecting JSON {id: 123} 
    // Or prefer query param? POST/DELETE with body is fine.
    
    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
         return MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT));
    }
    
    struct json_object *j_id;
    if (json_object_object_get_ex(root, "id", &j_id)) {
        int id = json_object_get_int(j_id);
        database_delete_api_key(ctx->db, id);
    }
    
    json_object_put(root);
    const char *json = "{\"status\":\"deleted\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json), (void*)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
    
}
