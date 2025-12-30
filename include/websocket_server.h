#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

#include <libwebsockets.h>
#include "../include/runtime_config.h"

// Initialize the WebSocket server context
int ws_server_init(struct runtime_config *config);

// Start the WebSocket server loop (blocking or threaded)
void *ws_server_thread(void *arg);

// Cleanup WebSocket resources
void ws_server_cleanup();

// Broadcast a JSON message to all connected clients
void ws_broadcast_message(const char *json_message);

#endif // WEBSOCKET_SERVER_H
