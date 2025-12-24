#ifndef CONFIG_HANDLER_H
#define CONFIG_HANDLER_H

#include <net/if.h>

struct backend_config {
    char url[256];
    char api_key[64];
    char api_secret[64];
};

struct config {
    char app_secret[64];
    char interface[IF_NAMESIZE];
    int http_port;
    struct backend_config backend;
    char username[64];
    char password[64];
};

// Function to load configuration from a file
// Returns 0 on success, non-zero on failure
int load_config(const char *filename, struct config *cfg);

// Function to print configuration (for debugging)
void print_config(const struct config *cfg);

#endif // CONFIG_HANDLER_H