#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <uuid/uuid.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <json-c/json.h>
#include <microhttpd.h>
#include "../../include/api_handlers.h"
#include "../../include/database.h"
#include "../../include/common.h"

// Format: cyr_k_<random_chars>
static int generate_api_key(char *key_buffer, size_t buffer_size) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const size_t charset_len = sizeof(charset) - 1;
    const unsigned char max_valid = (unsigned char)(256 - (256 % charset_len));

    if (!key_buffer || buffer_size < 16) return -1;

    snprintf(key_buffer, buffer_size, "cyr_k_");
    size_t pos = 6;

    while (pos < buffer_size - 1) {
        unsigned char rnd[32];
        if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
            return -1;
        }
        for (size_t j = 0; j < sizeof(rnd) && pos < buffer_size - 1; j++) {
            if (rnd[j] < max_valid) {
                key_buffer[pos++] = charset[rnd[j] % charset_len];
            }
        }
    }
    key_buffer[buffer_size - 1] = '\0';
    return 0;
}

void hash_api_key(const char *key, char *hash_out) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        hash_out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, key, strlen(key)) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        hash_out[0] = '\0';
        return;
    }

    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[64] = '\0';
}

// GET /api/v1/keys
enum MHD_Result api_keys_list(struct MHD_Connection *connection, struct api_context *ctx) {
    struct api_key_record *keys = NULL;
    int count = 0;

    if (!ctx || !ctx->db || database_list_api_keys(ctx->db, &keys, &count) != 0) {
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Database error");
    }

    struct json_object *j_array = json_object_new_array();
    for (int i = 0; i < count; i++) {
        struct json_object *j_key = json_object_new_object();
        json_object_object_add(j_key, "id", json_object_new_int(keys[i].id));
        json_object_object_add(j_key, "name", json_object_new_string(keys[i].name));
        json_object_object_add(j_key, "prefix", json_object_new_string(keys[i].key_prefix));
        json_object_object_add(j_key, "permissions", json_object_new_string(keys[i].permissions));
        json_object_object_add(j_key, "last_used_at", json_object_new_int64((int64_t)keys[i].last_used_at));
        json_object_object_add(j_key, "expires_at", json_object_new_int64((int64_t)keys[i].expires_at));
        json_object_object_add(j_key, "created_at", json_object_new_int64((int64_t)keys[i].created_at));
        json_object_array_add(j_array, j_key);
    }

    database_free_api_key_list(keys, count);

    const char *json_str = json_object_to_json_string(j_array);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(j_array);
    return ret;
}

// POST /api/v1/keys
enum MHD_Result api_keys_create(struct MHD_Connection *connection, struct api_context *ctx,
                                const char *upload_data, size_t size) {
    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    struct json_object *j_name = NULL, *j_perms = NULL, *j_expires = NULL;
    const char *name = "API Key";
    const char *perms = "read,write";
    time_t expires_at = 0;

    if (json_object_object_get_ex(root, "name", &j_name)) {
        const char *s = json_object_get_string(j_name);
        if (s && s[0]) name = s;
    }
    if (json_object_object_get_ex(root, "permissions", &j_perms)) {
        const char *s = json_object_get_string(j_perms);
        if (s && s[0]) perms = s;
    }
    if (json_object_object_get_ex(root, "expires_in_days", &j_expires)) {
        int days = json_object_get_int(j_expires);
        if (days > 0) expires_at = time(NULL) + ((time_t)days * 86400);
    }

    char raw_key[64];
    if (generate_api_key(raw_key, sizeof(raw_key)) != 0) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Key generation failed");
    }

    char key_hash[65];
    hash_api_key(raw_key, key_hash);
    if (key_hash[0] == '\0') {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Key hashing failed");
    }

    struct api_key_record key_record = {0};
    snprintf(key_record.name, sizeof(key_record.name), "%s", name);
    snprintf(key_record.key_hash, sizeof(key_record.key_hash), "%s", key_hash);
    snprintf(key_record.key_prefix, sizeof(key_record.key_prefix), "%.10s", raw_key);
    snprintf(key_record.permissions, sizeof(key_record.permissions), "%s", perms);
    key_record.expires_at = expires_at;

    if (!ctx || !ctx->db || database_create_api_key(ctx->db, &key_record) != 0) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Database error");
    }

    struct json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "api_key", json_object_new_string(raw_key));
    json_object_object_add(j_resp, "message", json_object_new_string("Save this key securely. It will not be shown again."));

    const char *json_str = json_object_to_json_string(j_resp);
    enum MHD_Result ret = api_send_json(connection, MHD_HTTP_OK, json_str);
    json_object_put(root);
    json_object_put(j_resp);
    return ret;
}

// DELETE /api/v1/keys
enum MHD_Result api_keys_delete(struct MHD_Connection *connection, struct api_context *ctx,
                                const char *upload_data, size_t size) {
    if (!upload_data || size == 0) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing request body");
    }

    struct json_object *root = json_tokener_parse(upload_data);
    if (!root) {
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid JSON");
    }

    struct json_object *j_id = NULL;
    if (!json_object_object_get_ex(root, "id", &j_id)) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Missing id field");
    }

    int id = json_object_get_int(j_id);
    if (id <= 0 || !ctx || !ctx->db || database_delete_api_key(ctx->db, id) != 0) {
        json_object_put(root);
        return api_send_error(connection, MHD_HTTP_NOT_FOUND, "API key not found");
    }

    json_object_put(root);
    return api_send_json(connection, MHD_HTTP_OK, "{\"status\":\"deleted\"}");
}
