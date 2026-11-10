#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include "../include/websocket_server.h"

static struct lws_context *context = NULL;
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

static int callback_cyrenus(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len) {
    (void)in;
    (void)len;
    struct pss_cyrenus *pss = (struct pss_cyrenus *)user;

    switch (reason) {
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

int ws_server_init(struct runtime_config *config) {
    struct lws_context_creation_info info;

    interrupted = 0;
    memset(&info, 0, sizeof(info));
    info.port = (config && config->http_port > 0) ? (int)(config->http_port + 1) : 8182;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "lws init failed on port %d\n", info.port);
        return -1;
    }

    printf("WebSocket server started on port %d\n", info.port);
    return 0;
}

void ws_server_cleanup() {
    interrupted = 1;
    if (context) {
        lws_cancel_service(context);
        lws_context_destroy(context);
        context = NULL;
    }
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
