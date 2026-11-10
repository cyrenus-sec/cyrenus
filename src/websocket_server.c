#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "../include/websocket_server.h"
#include "../include/attack_info.h"
#include "../include/api_handlers.h"

static struct lws_context *context = NULL;
static struct database *ws_db = NULL;
static char ws_bind_iface[IFNAMSIZ] = {0};
static volatile int interrupted = 0;

#define MAX_MSG_LEN 4096
#define WS_QUEUE_SIZE 32

static char msg_queue[WS_QUEUE_SIZE][MAX_MSG_LEN];
static uint64_t next_seq = 1;
static uint64_t server_seen_seq = 1;
static pthread_mutex_t broadcast_lock = PTHREAD_MUTEX_INITIALIZER;

struct pss_cyrenus {
    uint64_t next_send_seq;
};

static void url_decode_tok(const char *src, size_t src_len, char *dst, size_t dst_len) {
    size_t j = 0;
    for (size_t i = 0; i < src_len && j + 1 < dst_len; i++) {
        if (src[i] == '%' && i + 2 < src_len &&
            isxdigit((unsigned char)src[i + 1]) &&
            isxdigit((unsigned char)src[i + 2])) {
            char hex[3] = { src[i + 1], src[i + 2], '\0' };
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static int validate_ws_credential(const char *token) {
    if (!token || token[0] == '\0' || !ws_db || !ws_db->is_open) {
        return 0;
    }

    if (strncmp(token, "Bearer ", 7) == 0 || strncmp(token, "bearer ", 7) == 0) {
        token += 7;
    }
    while (*token && isspace((unsigned char)*token)) token++;
    if (token[0] == '\0') return 0;

    // 1. Check active session token
    struct session_record session;
    if (database_get_session(ws_db, token, &session) == 0) {
        if (time(NULL) < session.expires_at) {
            return 1;
        }
    }

    // 2. Fallback: Check API key
    char hash[65];
    hash_api_key(token, hash);
    if (hash[0] != '\0') {
        struct api_key_record key_rec;
        if (database_validate_api_key(ws_db, hash, &key_rec) == 0) {
            database_update_api_key_last_used(ws_db, key_rec.id);
            return 1;
        }
    }

    return 0;
}

static int extract_query_token(const char *args, char *out, size_t out_len) {
    if (!args || !out || out_len == 0) return -1;
    out[0] = '\0';

    const char *p = args;
    if (*p == '?') p++;

    while (*p) {
        const char *eq = strchr(p, '=');
        const char *amp = strchr(p, '&');
        size_t pair_end = amp ? (size_t)(amp - p) : strlen(p);

        if (eq && (size_t)(eq - p) < pair_end) {
            size_t key_len = (size_t)(eq - p);
            if (key_len == 5 && strncmp(p, "token", 5) == 0) {
                const char *val = eq + 1;
                size_t val_len = pair_end - key_len - 1;
                url_decode_tok(val, val_len, out, out_len);
                return out[0] ? 0 : -1;
            }
        }
        if (!amp) break;
        p = amp + 1;
    }
    return -1;
}

static int ws_authenticate_wsi(struct lws *wsi) {
    if (!wsi || !ws_db || !ws_db->is_open) return 0;

    // 1. Check ?token=<session_or_key> URL parameter
    char uri_args[512] = {0};
    if (lws_hdr_copy(wsi, uri_args, sizeof(uri_args), WSI_TOKEN_HTTP_URI_ARGS) > 0) {
        char tok[256] = {0};
        if (extract_query_token(uri_args, tok, sizeof(tok)) == 0 &&
            validate_ws_credential(tok)) {
            return 1;
        }
    }

    // Also parse query string out of WSI_TOKEN_GET_URI if proxy passed it there
    char get_uri[512] = {0};
    if (lws_hdr_copy(wsi, get_uri, sizeof(get_uri), WSI_TOKEN_GET_URI) > 0) {
        char *q = strchr(get_uri, '?');
        if (q) {
            char tok[256] = {0};
            if (extract_query_token(q + 1, tok, sizeof(tok)) == 0 &&
                validate_ws_credential(tok)) {
                return 1;
            }
        }
    }

    // 2. Check Authorization: Bearer <token>
    char auth_hdr[256] = {0};
    if (lws_hdr_copy(wsi, auth_hdr, sizeof(auth_hdr), WSI_TOKEN_HTTP_AUTHORIZATION) > 0) {
        if (validate_ws_credential(auth_hdr)) {
            return 1;
        }
    }

    // 3. Check custom X-API-Key header
    char xkey[256] = {0};
    if (lws_hdr_custom_copy(wsi, xkey, sizeof(xkey), "x-api-key:", 10) > 0) {
        if (validate_ws_credential(xkey)) {
            return 1;
        }
    }

    return 0;
}

static void resolve_iface_for_bind_addr(const char *bind_addr, char out_iface[IFNAMSIZ]) {
    out_iface[0] = '\0';
    if (!bind_addr || bind_addr[0] == '\0' ||
        strcmp(bind_addr, "0.0.0.0") == 0 || strcmp(bind_addr, "::") == 0) {
        return;
    }

    if (strcmp(bind_addr, "127.0.0.1") == 0 || strcmp(bind_addr, "::1") == 0) {
        snprintf(out_iface, IFNAMSIZ, "lo");
        return;
    }

    struct cyrenus_ip target;
    if (cyrenus_str_to_ip(bind_addr, &target, NULL) != 0) {
        return;
    }

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return;

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_name) continue;
        struct cyrenus_ip cur = {0};
        if (ifa->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)ifa->ifa_addr;
            cyrenus_ip_from_v4(&cur, sin->sin_addr.s_addr);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
            cyrenus_ip_from_v6(&cur, &sin6->sin6_addr);
        } else {
            continue;
        }
        if (cyrenus_ip_equals(&cur, &target)) {
            snprintf(out_iface, IFNAMSIZ, "%s", ifa->ifa_name);
            break;
        }
    }

    freeifaddrs(ifaddr);
}

static int callback_cyrenus(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len) {
    (void)in;
    (void)len;
    struct pss_cyrenus *pss = (struct pss_cyrenus *)user;

    switch (reason) {
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
            if (!ws_authenticate_wsi(wsi)) {
                lwsl_warn("Cyrenus WS: rejected unauthenticated WebSocket upgrade\n");
                return -1;
            }
            break;

        case LWS_CALLBACK_ESTABLISHED:
            pthread_mutex_lock(&broadcast_lock);
            pss->next_send_seq = next_seq;
            pthread_mutex_unlock(&broadcast_lock);
            break;

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            char local_buf[MAX_MSG_LEN];
            int has_msg = 0;
            int more_pending = 0;

            pthread_mutex_lock(&broadcast_lock);
            if (pss->next_send_seq < next_seq) {
                uint64_t earliest = (next_seq > WS_QUEUE_SIZE) ? (next_seq - WS_QUEUE_SIZE) : 1;
                if (pss->next_send_seq < earliest) {
                    pss->next_send_seq = earliest;
                }
                size_t idx = (size_t)(pss->next_send_seq % WS_QUEUE_SIZE);
                snprintf(local_buf, sizeof(local_buf), "%s", msg_queue[idx]);
                pss->next_send_seq++;
                has_msg = 1;
                more_pending = (pss->next_send_seq < next_seq);
            }
            pthread_mutex_unlock(&broadcast_lock);

            if (has_msg) {
                unsigned char buf[LWS_PRE + MAX_MSG_LEN];
                unsigned char *p = &buf[LWS_PRE];
                size_t msg_len = strlen(local_buf);
                if (msg_len > MAX_MSG_LEN - 1) msg_len = MAX_MSG_LEN - 1;
                memcpy(p, local_buf, msg_len);
                p[msg_len] = '\0';

                int n = lws_write(wsi, p, msg_len, LWS_WRITE_TEXT);
                if (n < (int)msg_len) {
                    fprintf(stderr, "ERROR writing to WS socket\n");
                }
                if (more_pending) {
                    lws_callback_on_writable(wsi);
                }
            }
            break;
        }

        default:
            break;
    }

    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "lws-cyrenus-protocol",
        callback_cyrenus,
        sizeof(struct pss_cyrenus),
        MAX_MSG_LEN,
        0, NULL, 0
    },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

int ws_server_init(struct runtime_config *config, struct database *db) {
    struct lws_context_creation_info info;

    ws_db = db;
    interrupted = 0;
    memset(&info, 0, sizeof(info));
    info.port = (config && config->http_port > 0) ? (int)(config->http_port + 1) : 8182;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    if (config && config->bind_address[0]) {
        resolve_iface_for_bind_addr(config->bind_address, ws_bind_iface);
        if (ws_bind_iface[0] != '\0') {
            info.iface = ws_bind_iface;
        }
    }

    context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "lws init failed on port %d\n", info.port);
        return -1;
    }

    printf("WebSocket server started on port %d (iface=%s, auth=required)\n",
           info.port, ws_bind_iface[0] ? ws_bind_iface : "all");
    return 0;
}

void ws_server_cleanup(void) {
    interrupted = 1;
    if (context) {
        lws_cancel_service(context);
        lws_context_destroy(context);
        context = NULL;
    }
    ws_db = NULL;
}

void ws_broadcast_message(const char *json_message) {
    if (!json_message || !context) return;

    pthread_mutex_lock(&broadcast_lock);
    size_t idx = (size_t)(next_seq % WS_QUEUE_SIZE);
    snprintf(msg_queue[idx], MAX_MSG_LEN, "%s", json_message);
    next_seq++;
    pthread_mutex_unlock(&broadcast_lock);

    lws_cancel_service(context);
}

void *ws_server_thread_impl(void *arg) {
    (void)arg;
    while (!interrupted && context) {
        lws_service(context, 50);

        pthread_mutex_lock(&broadcast_lock);
        uint64_t current = next_seq;
        pthread_mutex_unlock(&broadcast_lock);

        if (server_seen_seq < current && context) {
            lws_callback_on_writable_all_protocol(context, &protocols[0]);
            server_seen_seq = current;
        }
    }
    return NULL;
}

void *ws_server_thread(void *arg) {
    return ws_server_thread_impl(arg);
}
