 #include "../include/attack_info.h" // Include the new attack_info header

#include "../include/http_server.h"
#include "../include/common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <microhttpd.h>
#include <json-c/json.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <uuid/uuid.h>

 
#define TOKEN_EXPIRY 3600  // 1 hour
#define MAX_SESSIONS 1000  // Maximum number of concurrent sessions


static struct session sessions[MAX_SESSIONS] = {0};
static int session_count = 0;


#define XDP_PASS 2
#define XDP_DROP 1


 


static int map_fd_rules, map_fd_traffic;
// Add these new map file descriptors
int map_fd_udp_flood, map_fd_dns_track, map_fd_syn_flood;
  int map_fd_attack_info_array;
  int map_fd_attack_count;
static struct config* app_config;


void dump_bpf_map(int map_fd) {
    struct rule_key_t key = {0}, next_key = {0};
    struct rule_t value;

    printf("Dumping BPF map contents:\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("  Key: IP=0x%08X (%s), Port=%u, Proto=%u\n", 
                   ntohl(next_key.ip), inet_ntoa((struct in_addr){next_key.ip}), 
                   ntohs(next_key.port), next_key.proto);
          
        }
        key = next_key;
    }
}


static enum MHD_Result send_response(struct MHD_Connection *connection, const char *page, int status_code) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void*)page, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

static void generate_uuid(char *uuid_str) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);
}

static const char* generate_token(const char* username) {
    if (session_count >= MAX_SESSIONS) {
        // Handle session limit reached
        return NULL;
    }

    struct session* new_session = &sessions[session_count++];

    // Generate unique user ID and session ID
    generate_uuid(new_session->user_id);
    generate_uuid(new_session->session_id);

    time_t now = time(NULL);
    char data[256];
    unsigned char random_bytes[16];
    RAND_bytes(random_bytes, sizeof(random_bytes));

    snprintf(data, sizeof(data), "%s%s%s%ld%s%s", 
             username, 
             new_session->user_id, 
             new_session->session_id, 
             now, 
             app_config->app_secret,
             random_bytes);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, strlen(data), hash);
    
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(new_session->token + (i * 2), "%02x", hash[i]);
    }
    new_session->expiry = now + TOKEN_EXPIRY;
    
    return new_session->token;
}



static int verify_token(const char* token) {
    time_t now = time(NULL);
    for (int i = 0; i < session_count; i++) {
        if (strcmp(token, sessions[i].token) == 0) {
            if (now < sessions[i].expiry) {
                return 1;  // Valid token
            } else {
                // Token expired, remove the session
                memmove(&sessions[i], &sessions[i+1], (session_count - i - 1) * sizeof(struct session));
                session_count--;
                return 0;
            }
        }
    }
    return 0;  // Token not found
}


static void cleanup_expired_sessions() {
    time_t now = time(NULL);
    int i = 0;
    while (i < session_count) {
        if (now >= sessions[i].expiry) {
            // Remove expired session
            memmove(&sessions[i], &sessions[i+1], (session_count - i - 1) * sizeof(struct session));
            session_count--;
        } else {
            i++;
        }
    }
}

static enum MHD_Result handle_get_attacks(struct MHD_Connection *connection) {
    fprintf(stderr, "Entering handle_get_attacks\n");
    
    json_object *json_attacks = json_object_new_array();
    
    struct attack_info *attacks = NULL;
        int attack_count = get_attack_info(&attacks, map_fd_attack_info_array, map_fd_attack_count);
   // int attack_count = get_attack_info(&attacks);
    
    fprintf(stderr, "Retrieved %d attacks\n", attack_count);
    
    if (attacks == NULL) {
        fprintf(stderr, "Error: attacks pointer is NULL\n");
        json_object_put(json_attacks);
        return send_response(connection, "{\"error\":\"Internal server error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    for (int i = 0; i < sizeof(attacks); i++) {  
        json_object *json_attack = json_object_new_object();
        
        char time_str[30];
        time_t timestamp = (time_t)(attacks[i].timestamp / 1000000000); // Convert nanoseconds to seconds
        struct tm *tm_info = localtime(&timestamp);
        if (tm_info) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            snprintf(time_str, sizeof(time_str), "Invalid timestamp");
        }
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(attacks[i].src_ip), ip_str, sizeof(ip_str));
        
        json_object_object_add(json_attack, "timestamp", json_object_new_string(time_str));
        json_object_object_add(json_attack, "src_ip", json_object_new_string(ip_str));
        json_object_object_add(json_attack, "protocol", json_object_new_string(get_proto_name(attacks[i].protocol)));
        json_object_object_add(json_attack, "packets", json_object_new_int(attacks[i].packets));
        json_object_object_add(json_attack, "bytes", json_object_new_int64(attacks[i].bytes));
        
        json_object_array_add(json_attacks, json_attack);
        
        fprintf(stderr, "Added attack from %s\n", ip_str);
    }
    
    const char *json_str = json_object_to_json_string_ext(json_attacks, JSON_C_TO_STRING_PRETTY);
    fprintf(stderr, "JSON response: %s\n", json_str);
    
    enum MHD_Result ret = send_response(connection, json_str, MHD_HTTP_OK);
    
    json_object_put(json_attacks);
    free(attacks);
    
    fprintf(stderr, "Exiting handle_get_attacks\n");
    return ret;
}
static void request_completed(void *cls, struct MHD_Connection *connection,
                              void **con_cls, enum MHD_RequestTerminationCode toe)
{
     /*
     
     
     */
      struct connection_info_struct *con_info = *con_cls;
    if (con_info == NULL) return;

    if (con_info->type == REQUEST_TYPE_POST_RULE) {
        free(con_info->data.post.data);
        con_info->data.post.data = NULL;
    }

    free(con_info);
    *con_cls = NULL;

    
    
 
}

static enum MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                                    const char *filename, const char *content_type,
                                    const char *transfer_encoding, const char *data, uint64_t off,
                                    size_t size)
{
    struct connection_info_struct *con_info = coninfo_cls;
    
    fprintf(stderr, "Entering iterate_post\n");
    
    if (con_info == NULL) {
        fprintf(stderr, "Error: con_info is NULL in iterate_post\n");
        return MHD_NO;
    }
    
    if (key == NULL || data == NULL) {
        fprintf(stderr, "Error: key or data is NULL in iterate_post\n");
        return MHD_NO;
    }
    
    fprintf(stderr, "Processing key: %s, data size: %zu\n", key, size);
    
    if (strcmp(key, "username") == 0) {
        size_t copy_size = size < (MAX_USERNAME_LENGTH - 1) ? size : (MAX_USERNAME_LENGTH - 1);
        memcpy(con_info->data.login.username, data, copy_size);
        con_info->data.login.username[copy_size] = '\0';
        fprintf(stderr, "Username set, length: %zu\n", strlen(con_info->data.login.username));
    } else if (strcmp(key, "password") == 0) {
        size_t copy_size = size < (MAX_PASSWORD_LENGTH - 1) ? size : (MAX_PASSWORD_LENGTH - 1);
        memcpy(con_info->data.login.password, data, copy_size);
        con_info->data.login.password[copy_size] = '\0';
        fprintf(stderr, "Password set, length: %zu\n", strlen(con_info->data.login.password));
    } else {
        fprintf(stderr, "Unknown key: %s\n", key);
    }
    
    fprintf(stderr, "Exiting iterate_post\n");
    return MHD_YES;
}


static enum MHD_Result handle_login(struct MHD_Connection *connection,
                                    const char *url,
                                    const char *method,
                                    const char *version,
                                    const char *upload_data,
                                    size_t *upload_data_size,
                                    void **con_cls)
{
    fprintf(stderr, "Entering handle_login\n");
    
    if (connection == NULL || con_cls == NULL) {
        fprintf(stderr, "Error: connection or con_cls is NULL\n");
        return MHD_NO;
    }

    fprintf(stderr, "con_cls pointer: %p\n", (void*)con_cls);
    fprintf(stderr, "*con_cls value: %p\n", (void*)*con_cls);

    struct connection_info_struct *con_info = *con_cls;

    if (con_info == NULL) {
        fprintf(stderr, "Creating new connection_info_struct\n");
        con_info = calloc(1, sizeof(struct connection_info_struct));
        if (con_info == NULL) {
            fprintf(stderr, "Failed to allocate connection_info_struct\n");
            return MHD_NO;
        }
        fprintf(stderr, "Created new connection_info_struct at %p\n", (void*)con_info);
        
        con_info->type = REQUEST_TYPE_LOGIN;
        con_info->postprocessor = MHD_create_post_processor(connection, 1024, iterate_post, (void*)con_info);
        if (con_info->postprocessor == NULL) {
            fprintf(stderr, "Failed to create post processor\n");
            free(con_info);
            return MHD_NO;
        }
        *con_cls = (void*)con_info;
        fprintf(stderr, "Set *con_cls to %p\n", (void*)*con_cls);
        return MHD_YES;
    }

    fprintf(stderr, "Using existing connection_info_struct at %p\n", (void*)con_info);

    if (method == NULL) {
        fprintf(stderr, "Error: method is NULL\n");
        return MHD_NO;
    }

    fprintf(stderr, "HTTP method: %s\n", method);

    if (strcmp(method, "POST") != 0) {
        fprintf(stderr, "Method is not POST: %s\n", method);
        con_info->answerstring = strdup("Only POST is supported for login");
        if (con_info->answerstring == NULL) {
            fprintf(stderr, "Failed to allocate memory for answer string\n");
            return MHD_NO;
        }
        con_info->answercode = MHD_HTTP_METHOD_NOT_ALLOWED;
        return send_response(connection, con_info->answerstring, con_info->answercode);
    }

    if (upload_data_size == NULL) {
        fprintf(stderr, "Error: upload_data_size is NULL\n");
        return MHD_NO;
    }

    fprintf(stderr, "upload_data_size: %zu\n", *upload_data_size);

    if (*upload_data_size != 0) {
        if (upload_data == NULL) {
            fprintf(stderr, "Error: upload_data is NULL\n");
            return MHD_NO;
        }
        if (con_info->postprocessor == NULL) {
            fprintf(stderr, "Error: postprocessor is NULL\n");
            return MHD_NO;
        }
        MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    fprintf(stderr, "Finished processing POST data\n");
    fprintf(stderr, "Username length: %zu, Password length: %zu\n", 
            strnlen(con_info->data.login.username, MAX_USERNAME_LENGTH),
            strnlen(con_info->data.login.password, MAX_PASSWORD_LENGTH));

    if (con_info->data.login.username[0] && con_info->data.login.password[0]) {
        fprintf(stderr, "Checking credentials\n");
        if (strcmp(con_info->data.login.username, app_config->username) == 0 &&
            strcmp(con_info->data.login.password, app_config->password) == 0) {
            fprintf(stderr, "Credentials valid\n");
            cleanup_expired_sessions();
            const char* token = generate_token(con_info->data.login.username);
            if (!token) {
                fprintf(stderr, "Failed to generate token\n");
                con_info->answerstring = strdup("{\"error\":\"Failed to generate token\"}");
                con_info->answercode = MHD_HTTP_SERVICE_UNAVAILABLE;
            } else {
                fprintf(stderr, "Token generated successfully\n");
                con_info->answerstring = malloc(256);
                if (con_info->answerstring) {
                    snprintf(con_info->answerstring, 256, "{\"token\":\"%s\"}", token);
                    con_info->answercode = MHD_HTTP_OK;
                } else {
                    fprintf(stderr, "Failed to allocate memory for answer string\n");
                    con_info->answerstring = strdup("{\"error\":\"Internal server error\"}");
                    con_info->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        } else {
            fprintf(stderr, "Invalid credentials\n");
            con_info->answerstring = strdup("{\"error\":\"Invalid credentials\"}");
            con_info->answercode = MHD_HTTP_UNAUTHORIZED;
        }
    } else {
        fprintf(stderr, "Missing username or password\n");
        con_info->answerstring = strdup("{\"error\":\"Missing username or password\"}");
        con_info->answercode = MHD_HTTP_BAD_REQUEST;
    }

    fprintf(stderr, "Sending response: %s\n", con_info->answerstring);
    return send_response(connection, con_info->answerstring, con_info->answercode);
}
 

static enum MHD_Result handle_get_rules(struct MHD_Connection *connection) {
    json_object *json_rules = json_object_new_array();
    
    struct rule_key_t key = {0}, next_key = {0};
    struct rule_t rule;
    while (bpf_map_get_next_key(map_fd_rules, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd_rules, &next_key, &rule) == 0) {
            json_object *json_rule = json_object_new_object();
            json_object_object_add(json_rule, "ip", json_object_new_string(inet_ntoa((struct in_addr){next_key.ip})));
          
            json_object_object_add(json_rule, "port", json_object_new_int(next_key.port));
 
            json_object_object_add(json_rule, "proto", json_object_new_string(get_proto_name(next_key.proto)));
            json_object_object_add(json_rule, "port_start", json_object_new_int(rule.port_start));
            json_object_object_add(json_rule, "port_end", json_object_new_int(rule.port_end));
            json_object_object_add(json_rule, "action", json_object_new_int(rule.action));
            json_object_array_add(json_rules, json_rule);
        }
        key = next_key;
    }

    const char *json_str = json_object_to_json_string(json_rules);
    enum MHD_Result ret = send_response(connection, json_str, MHD_HTTP_OK);
    json_object_put(json_rules);
    return ret;
}
 


/*
static enum MHD_Result iterate_post_rule(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                                         const char *filename, const char *content_type,
                                         const char *transfer_encoding, const char *data, uint64_t off,
                                         size_t size)
{
    struct connection_info_struct *con_info = coninfo_cls;
    
    fprintf(stderr, "Entering iterate_post_rule\n");
    fprintf(stderr, "coninfo_cls: %p\n", coninfo_cls);
    fprintf(stderr, "Kind: %d, Key: %s, Filename: %s, Content-Type: %s\n", 
            kind, key ? key : "NULL", filename ? filename : "NULL", content_type ? content_type : "NULL");
    fprintf(stderr, "Transfer-Encoding: %s, Data size: %zu, Offset: %llu\n", 
            transfer_encoding ? transfer_encoding : "NULL", size, (unsigned long long)off);

    if (con_info == NULL) {
        fprintf(stderr, "Error: con_info is NULL in iterate_post_rule\n");
        return MHD_NO;
    }

    if (con_info->type != REQUEST_TYPE_POST_RULE) {
        fprintf(stderr, "Error: Unexpected request type in iterate_post_rule\n");
        return MHD_NO;
    }

    if (con_info->data.post.data == NULL) {
        fprintf(stderr, "Error: post data buffer is NULL\n");
        return MHD_NO;
    }

    if (con_info->data.post.data_size + size > MAX_POST_DATA_SIZE) {
        fprintf(stderr, "POST data exceeds maximum allowed size\n");
        return MHD_NO;
    }

    if (data != NULL && size > 0) {
        memcpy(con_info->data.post.data + con_info->data.post.data_size, data, size);
        con_info->data.post.data_size += size;
        con_info->data.post.data[con_info->data.post.data_size] = '\0';

        fprintf(stderr, "Updated post data size: %zu\n", con_info->data.post.data_size);
        fprintf(stderr, "Current post data: %s\n", con_info->data.post.data);
    } else {
        fprintf(stderr, "Warning: No data received in this iteration\n");
    }
    
    return MHD_YES;
}
*/
static enum MHD_Result handle_post_rule(struct MHD_Connection *connection,
                                        const char *url,
                                        const char *method,
                                        const char *version,
                                        const char *upload_data,
                                        size_t *upload_data_size,
                                        void **con_cls)
{
    struct connection_info_struct *con_info;
    
    fprintf(stderr, "Entering handle_post_rule\n");
    fprintf(stderr, "con_cls pointer: %p\n", (void*)con_cls);
    fprintf(stderr, "*con_cls value: %p\n", (void*)*con_cls);
    fprintf(stderr, "upload_data_size: %zu\n", *upload_data_size);
    
    if (con_cls == NULL) {
        fprintf(stderr, "Error: con_cls is NULL\n");
        return send_response(connection, "Internal Server Error", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (strcmp(method, "POST") != 0) {
        fprintf(stderr, "Error: Method is not POST\n");
        return send_response(connection, "Method Not Allowed", MHD_HTTP_METHOD_NOT_ALLOWED);
    }

    const char *content_type = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Type");
    if (content_type == NULL || strcmp(content_type, "application/json") != 0) {
        fprintf(stderr, "Error: Content-Type is not application/json\n");
        return send_response(connection, "Bad Request: Content-Type must be application/json", MHD_HTTP_BAD_REQUEST);
    }

    con_info = *con_cls;

    if (con_info == NULL) {
        fprintf(stderr, "Creating new connection_info_struct\n");
        con_info = calloc(1, sizeof(struct connection_info_struct));
        if (con_info == NULL) {
            fprintf(stderr, "Failed to allocate connection_info_struct\n");
            return send_response(connection, "Internal Server Error", MHD_HTTP_INTERNAL_SERVER_ERROR);
        }
        
        con_info->type = REQUEST_TYPE_POST_RULE;
        con_info->data.post.data = malloc(MAX_POST_DATA_SIZE);
        if (con_info->data.post.data == NULL) {
            fprintf(stderr, "Failed to allocate post data buffer\n");
            free(con_info);
            return send_response(connection, "Internal Server Error", MHD_HTTP_INTERNAL_SERVER_ERROR);
        }
        con_info->data.post.data[0] = '\0';
        con_info->data.post.data_size = 0;
        
        *con_cls = (void*)con_info;
        fprintf(stderr, "Set *con_cls to %p\n", (void*)*con_cls);
        return MHD_YES;
    }

    fprintf(stderr, "Using existing connection_info_struct at %p\n", (void*)con_info);

    if (*upload_data_size != 0) {
        fprintf(stderr, "Processing %zu bytes of upload data\n", *upload_data_size);
        
        // Check if we have enough space in the buffer
        if (con_info->data.post.data_size + *upload_data_size > MAX_POST_DATA_SIZE) {
            fprintf(stderr, "Error: POST data exceeds maximum allowed size\n");
            return send_response(connection, "Request Entity Too Large", MHD_HTTP_CONTENT_TOO_LARGE);
        }
        
        // Append the new data to our buffer
        memcpy(con_info->data.post.data + con_info->data.post.data_size, upload_data, *upload_data_size);
        con_info->data.post.data_size += *upload_data_size;
        con_info->data.post.data[con_info->data.post.data_size] = '\0';  // Null-terminate the string
        
        *upload_data_size = 0;
        return MHD_YES;
    }

    fprintf(stderr, "All data received, processing rule\n");

    if (con_info->data.post.data == NULL || con_info->data.post.data_size == 0) {
        fprintf(stderr, "No data received. post_data: %p, post_data_size: %zu\n", 
                (void*)con_info->data.post.data, con_info->data.post.data_size);
        return send_response(connection, "No data received", MHD_HTTP_BAD_REQUEST);
    }

    fprintf(stderr, "Received POST data (size: %zu): %s\n", con_info->data.post.data_size, con_info->data.post.data);

    // Parse the JSON data
    json_object *json_rule = json_tokener_parse(con_info->data.post.data);
    if (json_rule == NULL) {
        fprintf(stderr, "Failed to parse JSON data\n");
        return send_response(connection, "Invalid JSON", MHD_HTTP_BAD_REQUEST);
    }

    // Process the rule
    struct rule_t rule = {0};
    struct rule_key_t key = {0};

    // Parse IP
    json_object *json_ip;
    if (json_object_object_get_ex(json_rule, "ip", &json_ip)) {
        const char *ip_str = json_object_get_string(json_ip);
        if (inet_pton(AF_INET, ip_str, &key.ip) != 1) {
            json_object_put(json_rule);
            return send_response(connection, "Invalid IP address", MHD_HTTP_BAD_REQUEST);
        }
    } else {
        json_object_put(json_rule);
        return send_response(connection, "Missing IP address", MHD_HTTP_BAD_REQUEST);
    }

    // Parse port (0 means any port)
    json_object *json_port;
    if (json_object_object_get_ex(json_rule, "port", &json_port)) {
        int port = json_object_get_int(json_port);
        key.port = htons(port);
        rule.port_start = htons(port);
        rule.port_end = htons(port);
    } else {
        key.port = 0;
        rule.port_start = 0;
        rule.port_end = 0;
    }

    // Parse protocol
    json_object *json_proto;
    if (json_object_object_get_ex(json_rule, "proto", &json_proto)) {
        const char *proto_str = json_object_get_string(json_proto);
        if (strcasecmp(proto_str, "tcp") == 0) key.proto = IPPROTO_TCP;
        else if (strcasecmp(proto_str, "udp") == 0) key.proto = IPPROTO_UDP;
        else if (strcasecmp(proto_str, "icmp") == 0) key.proto = IPPROTO_ICMP;
        else if (strcasecmp(proto_str, "any") == 0) key.proto = 0;
        else {
            json_object_put(json_rule);
            return send_response(connection, "Invalid protocol", MHD_HTTP_BAD_REQUEST);
        }
    } else {
        key.proto = 0;  // Default to any protocol
    }
    rule.proto = key.proto;

    // Parse action
    json_object *json_action;
    if (json_object_object_get_ex(json_rule, "action", &json_action)) {
        const char *action_str = json_object_get_string(json_action);
        if (strcasecmp(action_str, "pass") == 0) rule.action = XDP_PASS;
        else if (strcasecmp(action_str, "drop") == 0) rule.action = XDP_DROP;
        else {
            json_object_put(json_rule);
            return send_response(connection, "Invalid action", MHD_HTTP_BAD_REQUEST);
        }
    } else {
        rule.action = XDP_DROP;  // Default action is to drop
    }

    json_object_put(json_rule);

    fprintf(stderr, "Adding rule: IP=0x%08X, Port_start=%u, Port_end=%u, Proto=%u, Action=%u\n",
           ntohl(key.ip), ntohs(rule.port_start), ntohs(rule.port_end), rule.proto, rule.action);

    if (bpf_map_update_elem(map_fd_rules, &key, &rule, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add rule to BPF map: %s\n", strerror(errno));
        return send_response(connection, "Failed to add rule", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }

    fprintf(stderr, "Rule added successfully\n");
    return send_response(connection, "Rule added successfully", MHD_HTTP_OK);
}

static enum MHD_Result handle_delete_rule(struct MHD_Connection *connection, const char *url) {
    struct rule_key_t key = {0};
    char ip_str[INET_ADDRSTRLEN];
    unsigned int proto;

    // Parse the rule key from the URL
    int parsed = sscanf(url, "/rules/%15[^_]_%hu_%u", ip_str, &key.port, &proto);
    if (parsed != 3) {
        printf("Failed to parse URL: %s\n", url);
        return send_response(connection, "Invalid URL format", MHD_HTTP_BAD_REQUEST);
    }

    // Convert IP string to network byte order
    if (inet_aton(ip_str, (struct in_addr *)&key.ip) == 0) {
        printf("Invalid IP address: %s\n", ip_str);
        return send_response(connection, "Invalid IP address", MHD_HTTP_BAD_REQUEST);
    }

    // Ensure proto fits in uint8_t
    if (proto > 255) {
        printf("Invalid protocol number: %u\n", proto);
        return send_response(connection, "Invalid protocol", MHD_HTTP_BAD_REQUEST);
    }
    key.proto = (uint8_t)proto;

    printf("Deleting rule: IP=0x%08X (%s), Port=%hu, Proto=%u\n", 
           ntohl(key.ip), inet_ntoa((struct in_addr){key.ip}), ntohs(key.port), key.proto);

    if (bpf_map_delete_elem(map_fd_rules, &key) != 0) {
        printf("Failed to delete rule from map: %s\n", strerror(errno));
        return send_response(connection, "Failed to delete rule", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }

    return send_response(connection, "Rule deleted successfully", MHD_HTTP_OK);
}

static enum MHD_Result handle_get_traffic(struct MHD_Connection *connection) {
    json_object *json_traffic = json_object_new_array();
    int count = 0;
    
    struct traffic_info_t info;
    __u64 key = 0, next_key = 0;
    
    printf("DEBUG: Attempting to retrieve traffic data\n");
    printf("DEBUG: map_fd_traffic = %d\n", map_fd_traffic);

    while (bpf_map_get_next_key(map_fd_traffic, &key, &next_key) == 0) {
        printf("DEBUG: Found key in map: %llu\n", (unsigned long long)next_key);
        if (bpf_map_lookup_elem(map_fd_traffic, &next_key, &info) == 0) {
            json_object *json_info = json_object_new_object();
            json_object_object_add(json_info, "src_ip", json_object_new_string(inet_ntoa((struct in_addr){info.src_ip})));
            json_object_object_add(json_info, "dst_ip", json_object_new_string(inet_ntoa((struct in_addr){info.dst_ip})));
            json_object_object_add(json_info, "src_port", json_object_new_int(info.src_port));
            json_object_object_add(json_info, "dst_port", json_object_new_int(info.dst_port));
            json_object_object_add(json_info, "timestamp", json_object_new_int64(info.timestamp));
            json_object_object_add(json_info, "direction", json_object_new_int(info.direction));
            json_object_object_add(json_info, "proto", json_object_new_string(get_proto_name(info.proto)));
            json_object_object_add(json_info, "bytes", json_object_new_int64(info.bytes));
            json_object_object_add(json_info, "packets", json_object_new_int(info.packets));
            
            // Add new fields
            json_object_object_add(json_info, "flow_start_time", json_object_new_int64(info.flow_start_time));
            json_object_object_add(json_info, "flow_end_time", json_object_new_int64(info.flow_end_time));
            json_object_object_add(json_info, "fwd_packets", json_object_new_int(info.fwd_packets));
            json_object_object_add(json_info, "bwd_packets", json_object_new_int(info.bwd_packets));
            json_object_object_add(json_info, "fwd_bytes", json_object_new_int64(info.fwd_bytes));
            json_object_object_add(json_info, "bwd_bytes", json_object_new_int64(info.bwd_bytes));
            json_object_object_add(json_info, "fwd_header_length", json_object_new_int(info.fwd_header_length));
            json_object_object_add(json_info, "bwd_header_length", json_object_new_int(info.bwd_header_length));
            json_object_object_add(json_info, "min_packet_length", json_object_new_int(info.min_packet_length));
            json_object_object_add(json_info, "max_packet_length", json_object_new_int(info.max_packet_length));
            json_object_object_add(json_info, "fwd_packet_length_max", json_object_new_int(info.fwd_packet_length_max));
            json_object_object_add(json_info, "fwd_packet_length_min", json_object_new_int(info.fwd_packet_length_min));
            json_object_object_add(json_info, "fwd_packet_length_sum", json_object_new_int(info.fwd_packet_length_sum));
            json_object_object_add(json_info, "bwd_packet_length_max", json_object_new_int(info.bwd_packet_length_max));
            json_object_object_add(json_info, "bwd_packet_length_min", json_object_new_int(info.bwd_packet_length_min));
            json_object_object_add(json_info, "bwd_packet_length_sum", json_object_new_int(info.bwd_packet_length_sum));
            json_object_object_add(json_info, "iat_sum", json_object_new_int(info.iat_sum));
            json_object_object_add(json_info, "fwd_iat_sum", json_object_new_int(info.fwd_iat_sum));
            json_object_object_add(json_info, "bwd_iat_sum", json_object_new_int(info.bwd_iat_sum));
            json_object_object_add(json_info, "fin_count", json_object_new_int(info.fin_count));
            json_object_object_add(json_info, "syn_count", json_object_new_int(info.syn_count));
            json_object_object_add(json_info, "rst_count", json_object_new_int(info.rst_count));
            json_object_object_add(json_info, "psh_count", json_object_new_int(info.psh_count));
            json_object_object_add(json_info, "ack_count", json_object_new_int(info.ack_count));
            json_object_object_add(json_info, "urg_count", json_object_new_int(info.urg_count));
            json_object_object_add(json_info, "cwe_count", json_object_new_int(info.cwe_count));
            json_object_object_add(json_info, "ece_count", json_object_new_int(info.ece_count));

            // Calculate derived statistics
            __u64 flow_duration = info.flow_end_time - info.flow_start_time;
            if (flow_duration > 0) {
                double flow_bytes_per_sec = (double)(info.fwd_bytes + info.bwd_bytes) / (flow_duration / 1e9);
                double flow_packets_per_sec = (double)(info.fwd_packets + info.bwd_packets) / (flow_duration / 1e9);
                json_object_object_add(json_info, "flow_bytes_per_sec", json_object_new_double(flow_bytes_per_sec));
                json_object_object_add(json_info, "flow_packets_per_sec", json_object_new_double(flow_packets_per_sec));
            }

            if (info.fwd_packets > 0) {
                double fwd_packet_length_mean = (double)info.fwd_packet_length_sum / info.fwd_packets;
                json_object_object_add(json_info, "fwd_packet_length_mean", json_object_new_double(fwd_packet_length_mean));
            }

            if (info.bwd_packets > 0) {
                double bwd_packet_length_mean = (double)info.bwd_packet_length_sum / info.bwd_packets;
                json_object_object_add(json_info, "bwd_packet_length_mean", json_object_new_double(bwd_packet_length_mean));
            }

            json_object_array_add(json_traffic, json_info);
            count++;
        } else {
            printf("DEBUG: Failed to lookup element for key %llu\n", (unsigned long long)next_key);
        }
        key = next_key;
    }

    printf("DEBUG: Retrieved %d traffic entries\n", count);

    const char *json_str = json_object_to_json_string(json_traffic);
    enum MHD_Result ret = send_response(connection, json_str, MHD_HTTP_OK);
    json_object_put(json_traffic);
    return ret;
}


static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls) {
    //struct MHD_Response *response;
  

    // Check if this is a new connection
     
 /*
    int ret;
    // Perform authentication check
    char *user, *pass;
    pass = NULL;
    user = MHD_basic_auth_get_username_password(connection, &pass);

    if (user == NULL || pass == NULL ||
        strcmp(user, app_config->username) != 0 ||
        strcmp(pass, app_config->password) != 0) {


   
        response = MHD_create_response_from_buffer(strlen("Unauthorized"),
                                                   (void *)"Unauthorized",
                                                   MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_basic_auth_fail_response(connection, "eBPF-App Realm", response);
        MHD_destroy_response(response);
        if (user) free(user);
        if (pass) free(pass);
        return ret;
    }

    // Free the auth strings
    if (user) free(user);
    if (pass) free(pass);
    */

   fprintf(stderr, "Entering handle_request\n");
    fprintf(stderr, "URL: %s, Method: %s\n", url, method);

    if (con_cls == NULL) {
        fprintf(stderr, "Error: con_cls is NULL in handle_request\n");
        return MHD_NO;
    }

    fprintf(stderr, "con_cls pointer in handle_request: %p\n", (void*)con_cls);
    fprintf(stderr, "*con_cls value in handle_request: %p\n", (void*)*con_cls);

    if (strcmp(url, "/api/login") == 0) {
        return handle_login(connection, url, method, version, upload_data, upload_data_size, con_cls);
    }
    
    
    const char *auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0 || !verify_token(auth_header + 7)) {
    //    return send_response(connection, "Unauthorized", MHD_HTTP_UNAUTHORIZED);
    }

    // If we get here, authentication was successful
    // Now handle the actual request
    if (strcmp(method, "GET") == 0) {
        if (strcmp(url, "/rules") == 0) {
            return handle_get_rules(connection);
        } else if (strcmp(url, "/traffic") == 0) {
            return handle_get_traffic(connection);
        }
        else if (strcmp(url, "/attacks") == 0) {
            return handle_get_attacks(connection);
        }
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(url, "/rules") == 0) {
            return handle_post_rule(connection, url, method, version, upload_data, upload_data_size, con_cls);
        }
    } else if (strcmp(method, "DELETE") == 0) {
        if (strncmp(url, "/rules/", 7) == 0) {
            return handle_delete_rule(connection, url);
        }
    }

    return send_response(connection, "Not Found", MHD_HTTP_NOT_FOUND);
}

struct MHD_Daemon* start_http_server(struct config* config, int rules_map_fd, int traffic_map_fd , int map_fd_udp_flood_fd ,  int map_fd_dns_track_fd , int map_fd_syn_flood_fd , int mp_attack_info_array ,  int attack_count) {
    app_config = config;
    map_fd_rules = rules_map_fd;
    map_fd_traffic = traffic_map_fd;
    map_fd_udp_flood = map_fd_udp_flood_fd;
    map_fd_dns_track = map_fd_dns_track_fd;
    map_fd_syn_flood = map_fd_syn_flood_fd;

   map_fd_attack_info_array = mp_attack_info_array;
   map_fd_attack_count = attack_count ;
/* 
   struct MHD_Daemon *daemon = MHD_start_daemon(
    MHD_USE_INTERNAL_POLLING_THREAD, config->http_port, NULL, NULL,
    &handle_request, NULL, 
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
        MHD_OPTION_END
    ); */
   struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, config->http_port, NULL, NULL,
                              &handle_request, NULL,
                              MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                              MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Failed to start HTTP server\n");
    } else {
        printf("HTTP server started on port %d\n", config->http_port);
    }
    
    return daemon;
}

void stop_http_server(struct MHD_Daemon* daemon) {
    if (daemon != NULL) {
        MHD_stop_daemon(daemon);
        printf("HTTP server stopped\n");
    }
}