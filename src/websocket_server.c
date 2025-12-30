#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "../include/websocket_server.h"

static struct lws_context *context = NULL;
static int interrupted = 0;

// Broadcast State
#define MAX_MSG_LEN 4096
static char broadcast_msg[MAX_MSG_LEN];
static int current_msg_id = 0;
static pthread_mutex_t broadcast_lock = PTHREAD_MUTEX_INITIALIZER;

struct pss_cyrenus {
    int last_msg_id;
};

// Callback using message versioning
static int callback_cyrenus(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len) {
    struct pss_cyrenus *pss = (struct pss_cyrenus *)user;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            pthread_mutex_lock(&broadcast_lock);
            pss->last_msg_id = current_msg_id; // Start caught up
            pthread_mutex_unlock(&broadcast_lock);
            break;

        case LWS_CALLBACK_SERVER_WRITEABLE:
            pthread_mutex_lock(&broadcast_lock);
            if (pss->last_msg_id < current_msg_id) {
                // Prepare buffer (LWS needs padding)
                unsigned char buf[LWS_PRE + MAX_MSG_LEN];
                unsigned char *p = &buf[LWS_PRE];
                size_t msg_len = strlen(broadcast_msg);
                
                if (msg_len > MAX_MSG_LEN - 1) msg_len = MAX_MSG_LEN - 1;
                memcpy(p, broadcast_msg, msg_len);
                p[msg_len] = '\0';
                
                // Write
                int n = lws_write(wsi, p, msg_len, LWS_WRITE_TEXT);
                if (n < (int)msg_len) {
                    fprintf(stderr, "ERROR writing to WS socket\n");
                }
                
                // Update client state
                pss->last_msg_id = current_msg_id;
            }
            pthread_mutex_unlock(&broadcast_lock);
            break; // Continue serving ? No need for special return.

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
    },
    { NULL, NULL, 0, 0 } /* terminator */
};

int ws_server_init(struct runtime_config *config) {
    struct lws_context_creation_info info;

    memset(&info, 0, sizeof info);
    // Running on separate port for now (standard WS port or incremented HTTP)
    info.port = 8182; 
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    // info.options = LWS_SERVER_OPTION_VALIDATE_UTF8; 

    context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "lws init failed\n");
        return -1;
    }

    printf("WebSocket server started on port %d\n", info.port);
    return 0;
}

void ws_server_cleanup() {
    interrupted = 1;
    if (context) {
        lws_context_destroy(context);
        context = NULL;
    }
}



void ws_broadcast_message(const char *json_message) {
    pthread_mutex_lock(&broadcast_lock);
    
    // Update global buffer
    snprintf(broadcast_msg, MAX_MSG_LEN, "%s", json_message);
    current_msg_id++;
    
    pthread_mutex_unlock(&broadcast_lock);
    
    // Trigger callbacks using lws_cancel_service logic 
    // or lws_callback_on_writable_all_protocol if context is accessible and thread-safe.
    // LWS guide says: user code tracks the context/wsi and calls callback_on_writable.
    // However, calling it from another thread is UNSAFE directly.
    // Correct way: lws_cancel_service(context) wakes up the loop, 
    // and inside the loop (PROTOCOL_INIT or dedicated callback) we handle triggers?
    // 
    // Better pattern for LWS < 4.x or simple usage:
    // Just use lws_cancel_service(context). 
    // But we need a way to tell the loop "hey, write to everyone".
    // 
    // LWS provides `lws_callback_on_writable_all_protocol` but it MUST be called from the service thread.
    // So:
    // 1. Set global flag/id (done).
    // 2. Wake up loop via lws_cancel_service(context).
    // 3. In the protocol callback handling LWS_CALLBACK_EVENT_WAIT_CANCELLED (if supported) 
    //    OR just rely on the timeout (100ms) to check the flag?
    
    // Let's rely on the SERVICE LOOP checking the global ID? 
    // No, standard `lws_service` blocks.
    // If we call `lws_cancel_service(context)`, it returns from wait immediately.
    // BUT we need to trigger `lws_callback_on_writable_all_protocol`.
    // Where?
    // We can't inject code into `lws_service`.
    // We can use a special "broadcast" protocol or add logic in an existing one?
    //
    // Actually, simply calling lws_callback_on_writable_all_protocol FROM THE SERVICE THREAD is the key.
    // So we need a mechanism to execute that function in the service thread.
    //
    // Simplified Hack for this MVP:
    // The `ws_server_thread` loop calls `lws_service(context, 100)`.
    // After `lws_service` returns (every 100ms or on event), we can check:
    // "Is there a pending broadcast?"
    // If yes, we call `lws_callback_on_writable_all_protocol` THERE (in the loop).
    // This is thread-safe because it occupies the same thread as lws_service!
}

// We need a separate variable to track "last broadcast version handled by server thread" 
// vs "current broadcast version".
// But `ws_server_thread` is in this file, so we can access statics.

static int server_last_msg_id = 0;

// Redefining thread function to handle the broadcast trigger
void *ws_server_thread_impl(void *arg) {
    while (!interrupted && context) {
        lws_service(context, 50); // 50ms poll
        
        pthread_mutex_lock(&broadcast_lock);
        int current = current_msg_id;
        pthread_mutex_unlock(&broadcast_lock);
        
        if (server_last_msg_id < current) {
            lws_callback_on_writable_all_protocol(context, &protocols[0]);
            server_last_msg_id = current; 
        }
    }
    return NULL;
}

// Overwrite the previous stub
void *ws_server_thread(void *arg) {
    return ws_server_thread_impl(arg);
}
