#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <microhttpd.h>
#include "config_handler.h"
#include "runtime_config.h"
#include "database.h"
#include "api_handlers.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct MHD_Daemon *start_http_server(
    struct runtime_config *config,
    struct database *db,
    const struct map_fds *fds
);

void stop_http_server(struct MHD_Daemon *daemon);

#define MAX_USERNAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_POST_DATA_SIZE 4024 * 4024

#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_NOT_FOUND 404
#define HTTP_INTERNAL_SERVER_ERROR 500

#define MAX_PAYLOAD_SIZE 1024 * 1024
#define MAX_URL_LENGTH 2048

#endif // HTTP_SERVER_H
