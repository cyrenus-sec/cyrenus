#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <microhttpd.h>
#include "config_handler.h"

/*
    macros
*/
#define MIN(a,b) ((a) < (b) ? (a) : (b))
// Function to start the HTTP server
struct MHD_Daemon* start_http_server(struct config* config, int rules_map_fd, int traffic_map_fd , int map_fd_udp_flood_fd ,  int map_fd_dns_track_fd , int map_fd_syn_flood_fd , int  map_fd_attack_info_array, int map_fd_attack_count);

// Function to stop the HTTP server
void stop_http_server(struct MHD_Daemon* daemon);

// Structure to hold connection-specific information

#define MAX_USERNAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_POST_DATA_SIZE 4024 * 4024 

  


enum request_type {
    REQUEST_TYPE_LOGIN,
    REQUEST_TYPE_POST_RULE,
    REQUEST_TYPE_OTHER
};

struct login_data {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
};

struct post_data {
    char *data;
    size_t data_size;
};

struct connection_info_struct {
    enum request_type type;
    union {
        struct login_data login;
        struct post_data post;
    } data;
    char *answerstring;
    int answercode;
    struct MHD_PostProcessor *postprocessor;
};


// Constants for HTTP response codes
#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_NOT_FOUND 404
#define HTTP_INTERNAL_SERVER_ERROR 500

// Constants for maximum sizes
#define MAX_PAYLOAD_SIZE 1024 * 1024  // 1MB max payload size
#define MAX_URL_LENGTH 2048

#endif // HTTP_SERVER_H