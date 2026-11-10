#include "../include/http_server.h"
#include "../include/api_handlers.h"
#include "../include/common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <microhttpd.h>
#include <time.h>

// Embedded Web Assets
#include "../include/web_index.h"
#include "../include/web_login.h"
#include "../include/web_app.h"
#include "../include/web_styles.h"


// Global state
static struct runtime_config *app_config = NULL;
static struct database *app_db = NULL;
static struct map_fds app_fds;

// Request context for POST data
struct connection_context {
    struct api_context api_ctx;
    char *data;
    size_t size;
};

// MAX_PAYLOAD_SIZE is defined in http_server.h

// Helper: Reset BPF map FDs to -1
static void reset_app_fds(void) {
    app_fds.rules_fd = -1;
    app_fds.traffic_fd = -1;
    app_fds.udp_flood_fd = -1;
    app_fds.dns_track_fd = -1;
    app_fds.syn_flood_fd = -1;
    app_fds.attack_info_array_fd = -1;
    app_fds.attack_count_fd = -1;
    app_fds.active_attacks_fd = -1;
    app_fds.auto_block_fd = -1;
    app_fds.ip_whitelist_fd = -1;
    app_fds.ip_blacklist_fd = -1;
    app_fds.geoip_map_fd = -1;
    app_fds.blocked_countries_fd = -1;
    app_fds.global_stats_fd = -1;
    app_fds.config_map_fd = -1;
}

// --- Helper Functions ---

static enum MHD_Result send_response_options(struct MHD_Connection *connection) {
    struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With");

    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

static enum MHD_Result send_response_buffer(struct MHD_Connection *connection,
                                           const void *buffer,
                                           size_t size,
                                           const char *content_type) {
    struct MHD_Response *rs = MHD_create_response_from_buffer(size, (void*)buffer, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(rs, "Content-Type", content_type);
    MHD_add_response_header(rs, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(rs, "Cache-Control", "no-cache");

    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, rs);
    MHD_destroy_response(rs);
    return ret;
}

static enum MHD_Result queue_security_response(struct MHD_Connection *connection,
                                               struct MHD_Response *response) {
    if (!response) {
        api_security_last_status(); // Reset thread-local status
        return api_send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Internal Error");
    }
    unsigned int status = (unsigned int)api_security_last_status();
    enum MHD_Result ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return ret;
}

// --- Main Request Dispatcher ---

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls) {
                          
    struct connection_context *ctx = *con_cls;
    
    // 1. New connection
    if (ctx == NULL) {
        ctx = calloc(1, sizeof(struct connection_context));
        if (!ctx) return MHD_NO;
        
        // Initialize API context
        ctx->api_ctx.config = app_config;
        ctx->api_ctx.db = app_db;
        ctx->api_ctx.fds = &app_fds;
        
        *con_cls = ctx;
        return MHD_YES;
    }
    
    // 2. Receiving data (for POST/PUT)
    if (*upload_data_size > 0) {
        if (ctx->size + *upload_data_size > MAX_PAYLOAD_SIZE) {
            return MHD_NO; // Too large
        }
        
        char *new_data = realloc(ctx->data, ctx->size + *upload_data_size + 1);
        if (!new_data) return MHD_NO;
        
        ctx->data = new_data;
        memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
        ctx->size += *upload_data_size;
        ctx->data[ctx->size] = '\0';
        
        *upload_data_size = 0;
        return MHD_YES;
    }
    
    // 3. Process request (all data received)
    
    // Handle OPTIONS (CORS preflight)
    if (strcmp(method, "OPTIONS") == 0) {
        return send_response_options(connection);
    }
    
    // --- Public Routes ---
    
    if (strcmp(url, "/api/v1/system/health") == 0) {
        return api_system_health(connection, &ctx->api_ctx);
    }
    
    if (strcmp(url, "/api/v1/auth/login") == 0 && strcmp(method, "POST") == 0) {
        return api_auth_login(connection, &ctx->api_ctx, ctx->data, ctx->size);
    }
    
    // --- Frontend Routing ---

    if (strcmp(method, "GET") == 0) {
        if (strcmp(url, "/") == 0 || strcmp(url, "/index.html") == 0) {
            return send_response_buffer(connection, index_html, index_html_len, "text/html; charset=utf-8");
        }
        if (strcmp(url, "/login.html") == 0 || strcmp(url, "/login") == 0) {
            return send_response_buffer(connection, login_html, login_html_len, "text/html; charset=utf-8");
        }
        if (strcmp(url, "/app.js") == 0) {
            return send_response_buffer(connection, app_js, app_js_len, "application/javascript; charset=utf-8");
        }
        if (strcmp(url, "/styles.css") == 0) {
            return send_response_buffer(connection, styles_css, styles_css_len, "text/css; charset=utf-8");
        }
    }

    // --- Authentication Check ---

    const char *auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");

    // Check for API verification endpoint
    if (strcmp(url, "/api/v1/auth/verify") == 0 && strcmp(method, "GET") == 0) {
        return api_auth_verify(connection, &ctx->api_ctx, auth_header);
    }

    // Checking auth for protected routes
    int authenticated = 0;
    if (auth_header) {
        struct session_record session;
        const char *token = auth_header;
        if (strncmp(token, "Bearer ", 7) == 0) token += 7;
        if (database_get_session(app_db, token, &session) == 0) {
            if (time(NULL) < session.expires_at) authenticated = 1;
        }
    }

    // Check X-API-Key if not authenticated yet
    if (!authenticated) {
        const char *api_key = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-API-Key");
        if (api_key) {
            char hash[65];
            hash_api_key(api_key, hash);
            struct api_key_record key_rec;
            if (database_validate_api_key(app_db, hash, &key_rec) == 0) {
                authenticated = 1;
                database_update_api_key_last_used(app_db, key_rec.id);
            }
        }
    }

    if (!authenticated) {
        return api_send_error(connection, MHD_HTTP_UNAUTHORIZED, "Unauthorized");
    }

    // --- Protected Routes ---

    if (strcmp(url, "/api/v1/auth/logout") == 0 && strcmp(method, "POST") == 0) {
        return api_auth_logout(connection, &ctx->api_ctx, auth_header);
    }

    if (strcmp(url, "/api/v1/system/stats") == 0 && strcmp(method, "GET") == 0) {
        return api_system_stats(connection, &ctx->api_ctx);
    }

    if (strcmp(url, "/api/v1/system/settings") == 0) {
        if (strcmp(method, "GET") == 0) return api_system_get_settings(connection, &ctx->api_ctx);
        if (strcmp(method, "POST") == 0) return api_system_update_settings(connection, &ctx->api_ctx, ctx->data, ctx->size);
    }

    if (strcmp(url, "/api/v1/attacks") == 0) {
        if (strcmp(method, "GET") == 0) return api_attacks_list(connection, &ctx->api_ctx, NULL, NULL);
        if (strcmp(method, "DELETE") == 0) return api_attacks_clear(connection, &ctx->api_ctx);
    }

    if (strncmp(url, "/api/v1/attacks/", 16) == 0) {
        const char *sub = url + 16;
        size_t sub_len = strlen(sub);
        if (sub_len > 8 && strcmp(sub + sub_len - 8, "/resolve") == 0 && strcmp(method, "POST") == 0) {
            char id_buf[64];
            size_t id_len = sub_len - 8;
            if (id_len == 0 || id_len >= sizeof(id_buf)) {
                return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid attack ID");
            }
            memcpy(id_buf, sub, id_len);
            id_buf[id_len] = '\0';
            return api_attacks_resolve(connection, &ctx->api_ctx, id_buf);
        }
        if (strcmp(method, "GET") == 0) {
            int id = atoi(sub);
            return api_attacks_get(connection, &ctx->api_ctx, id);
        }
    }

    if (strcmp(url, "/api/v1/blocks") == 0 && strcmp(method, "GET") == 0) {
        return api_blocks_list(connection, &ctx->api_ctx);
    }

    if (strncmp(url, "/api/v1/blocks/", 15) == 0 && strcmp(method, "DELETE") == 0) {
        return api_blocks_delete(connection, &ctx->api_ctx, url + 15);
    }

    if (strcmp(url, "/api/v1/traffic/stats") == 0 && strcmp(method, "GET") == 0) {
        return api_traffic_stats(connection, &ctx->api_ctx);
    }

    if (strcmp(url, "/api/v1/rules") == 0) {
        if (strcmp(method, "GET") == 0) return api_rules_list(connection, &ctx->api_ctx);
        if (strcmp(method, "POST") == 0) return api_rules_create(connection, &ctx->api_ctx, ctx->data, ctx->size);
    }

    if (strncmp(url, "/api/v1/rules/", 14) == 0 && strcmp(method, "DELETE") == 0) {
        return api_rules_delete(connection, &ctx->api_ctx, url + 14);
    }

    if (strcmp(url, "/api/v1/iplists") == 0 && strcmp(method, "POST") == 0) {
        return api_iplists_add(connection, &ctx->api_ctx, ctx->data, ctx->size);
    }

    if (strncmp(url, "/api/v1/iplists/", 16) == 0) {
        if (strcmp(method, "GET") == 0) {
            return api_iplists_get(connection, &ctx->api_ctx, url + 16);
        }
        if (strcmp(method, "DELETE") == 0) {
            return api_iplists_delete(connection, &ctx->api_ctx, atoi(url + 16));
        }
    }

    if (strcmp(url, "/api/v1/geoip/rules") == 0) {
        if (strcmp(method, "GET") == 0) return api_geoip_list_rules(connection, &ctx->api_ctx);
        if (strcmp(method, "POST") == 0) return api_geoip_add_rule(connection, &ctx->api_ctx, ctx->data, ctx->size);
    }

    if (strncmp(url, "/api/v1/geoip/rules/", 20) == 0 && strcmp(method, "DELETE") == 0) {
        return api_geoip_delete_rule(connection, &ctx->api_ctx, url + 20);
    }

    if (strncmp(url, "/api/v1/geoip/lookup/", 21) == 0 && strcmp(method, "GET") == 0) {
        return api_geoip_lookup(connection, &ctx->api_ctx, url + 21);
    }

    if (strcmp(url, "/api/v1/keys") == 0) {
        if (strcmp(method, "GET") == 0) return api_keys_list(connection, &ctx->api_ctx);
        if (strcmp(method, "POST") == 0) return api_keys_create(connection, &ctx->api_ctx, ctx->data, ctx->size);
        if (strcmp(method, "DELETE") == 0) return api_keys_delete(connection, &ctx->api_ctx, ctx->data, ctx->size);
    }

    // Security/Tetragon routes
    if (strcmp(url, "/api/v1/security/events") == 0 && strcmp(method, "GET") == 0) {
        return queue_security_response(connection, api_security_events_list(connection, method, url));
    }

    if (strcmp(url, "/api/v1/security/stats") == 0 && strcmp(method, "GET") == 0) {
        return queue_security_response(connection, api_security_stats(connection, method, url));
    }

    if (strcmp(url, "/api/v1/security/policies") == 0 && strcmp(method, "GET") == 0) {
        return queue_security_response(connection, api_security_policies_list(connection, method, url));
    }

    if (strncmp(url, "/api/v1/security/policy/", 24) == 0) {
        const char *policy_name = url + 24;
        const char *deploy_suffix = strstr(policy_name, "/deploy");

        // Check for /deploy suffix
        if (deploy_suffix && strcmp(deploy_suffix, "/deploy") == 0) {
            char name[256];
            size_t name_len = (size_t)(deploy_suffix - policy_name);
            if (name_len == 0 || name_len >= sizeof(name)) {
                return api_send_error(connection, MHD_HTTP_BAD_REQUEST, "Invalid policy name");
            }
            memcpy(name, policy_name, name_len);
            name[name_len] = '\0';
            if (strcmp(method, "POST") == 0) {
                return queue_security_response(connection, api_security_policy_deploy(connection, method, name));
            }
        } else {
            struct MHD_Response *response = NULL;
            if (strcmp(method, "GET") == 0) {
                response = api_security_policy_get(connection, method, url, policy_name);
            } else if (strcmp(method, "POST") == 0) {
                response = api_security_policy_save(connection, method, policy_name, ctx->data, ctx->size);
            } else if (strcmp(method, "DELETE") == 0) {
                response = api_security_policy_delete(connection, method, policy_name);
            } else {
                return api_send_error(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
            }
            return queue_security_response(connection, response);
        }
    }

    if (strcmp(url, "/api/v1/security/logs") == 0 && strcmp(method, "GET") == 0) {
        return queue_security_response(connection, api_security_logs(connection, method, url));
    }

    if (strcmp(url, "/api/v1/security/config") == 0) {
        struct MHD_Response *response = NULL;
        if (strcmp(method, "GET") == 0) {
            response = api_security_config_get(connection, method, url);
        } else if (strcmp(method, "POST") == 0) {
            response = api_security_config_save(connection, method, ctx->data, ctx->size);
        } else {
            return api_send_error(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
        }
        return queue_security_response(connection, response);
    }

    return api_send_error(connection, MHD_HTTP_NOT_FOUND, "Not Found");
}

static void request_completed(void *cls, struct MHD_Connection *connection,
                              void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;
    struct connection_context *ctx = *con_cls;
    if (ctx) {
        if (ctx->data) free(ctx->data);
        free(ctx);
    }
    *con_cls = NULL;
}

// --- Server Lifecycle ---

struct MHD_Daemon *start_http_server(
    struct runtime_config *config,
    struct database *db,
    const struct map_fds *fds
) {
    app_config = config;
    app_db = db;

    reset_app_fds();
    if (fds) {
        app_fds = *fds;
    }

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,
        app_config->http_port,
        NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        MHD_OPTION_END
    );

    if (daemon) {
        printf("HTTP server started on port %d\n", app_config->http_port);
    } else {
        fprintf(stderr, "Failed to start HTTP server\n");
    }

    return daemon;
}

void stop_http_server(struct MHD_Daemon *daemon) {
    if (daemon) {
        MHD_stop_daemon(daemon);
    }
}