#include "../include/config_handler.h"
#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int load_config(const char *filename, struct config *cfg) {
    config_t conf;
    config_init(&conf);

    if (!config_read_file(&conf, filename)) {
        fprintf(stderr, "Error reading config file: %s (line %d)\n", 
                config_error_text(&conf), config_error_line(&conf));
        config_destroy(&conf);
        return 1;
    }

    const char *str;

    // Load interface
    if (config_lookup_string(&conf, "interface", &str)) {
        strncpy(cfg->interface, str, IF_NAMESIZE - 1);
        cfg->interface[IF_NAMESIZE - 1] = '\0';
    } else {
        fprintf(stderr, "No 'interface' setting in configuration file.\n");
        config_destroy(&conf);
        return 1;
    }

    // Load HTTP port
    if (!config_lookup_int(&conf, "http_port", &cfg->http_port)) {
        fprintf(stderr, "No 'http_port' setting in configuration file.\n");
        config_destroy(&conf);
        return 1;
    }

    // Load backend configurations
    config_setting_t *backend = config_lookup(&conf, "backend");
    if (backend != NULL) {
        // Load backend URL
        if (config_setting_lookup_string(backend, "url", &str)) {
            strncpy(cfg->backend.url, str, sizeof(cfg->backend.url) - 1);
            cfg->backend.url[sizeof(cfg->backend.url) - 1] = '\0';
        } else {
            fprintf(stderr, "No 'backend.url' setting in configuration file.\n");
            config_destroy(&conf);
            return 1;
        }

        // Load API key
        if (config_setting_lookup_string(backend, "api_key", &str)) {
            strncpy(cfg->backend.api_key, str, sizeof(cfg->backend.api_key) - 1);
            cfg->backend.api_key[sizeof(cfg->backend.api_key) - 1] = '\0';
        } else {
            fprintf(stderr, "No 'backend.api_key' setting in configuration file.\n");
            config_destroy(&conf);
            return 1;
        }

        // Load API secret
        if (config_setting_lookup_string(backend, "api_secret", &str)) {
            strncpy(cfg->backend.api_secret, str, sizeof(cfg->backend.api_secret) - 1);
            cfg->backend.api_secret[sizeof(cfg->backend.api_secret) - 1] = '\0';
        } else {
            fprintf(stderr, "No 'backend.api_secret' setting in configuration file.\n");
            config_destroy(&conf);
            return 1;
        }
    } else {
        fprintf(stderr, "No 'backend' setting in configuration file.\n");
        config_destroy(&conf);
        return 1;
    }

    // Load username
    if (config_lookup_string(&conf, "username", &str)) {
        strncpy(cfg->username, str, sizeof(cfg->username) - 1);
        cfg->username[sizeof(cfg->username) - 1] = '\0';
    } else {
        fprintf(stderr, "No 'username' setting in configuration file.\n");
        config_destroy(&conf);
        return 1;
    }

    // Load password
    if (config_lookup_string(&conf, "password", &str)) {
        strncpy(cfg->password, str, sizeof(cfg->password) - 1);
        cfg->password[sizeof(cfg->password) - 1] = '\0';
    } else {
        fprintf(stderr, "No 'password' setting in configuration file.\n");
        config_destroy(&conf);
        return 1;
    }

    config_destroy(&conf);
    return 0;
}

void print_config(const struct config *cfg) {
    printf("Configuration:\n");
    printf("  Interface: %s\n", cfg->interface);
    printf("  HTTP Port: %d\n", cfg->http_port);
    printf("  Backend URL: %s\n", cfg->backend.url);
    printf("  Backend API Key: %s\n", cfg->backend.api_key);
    printf("  Backend API Secret: %s\n", cfg->backend.api_secret);
    printf("  Username: %s\n", cfg->username);
    printf("  Password: %s\n", cfg->password);
}
