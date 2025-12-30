#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <libconfig.h>
#include "../include/runtime_config.h"
#include "../include/config_handler.h"

#define CYRENUS_VERSION "2.0.0"
#define CYRENUS_BUILD_DATE __DATE__

// Initialize runtime configuration with defaults
void runtime_config_init(struct runtime_config *rc) {
    memset(rc, 0, sizeof(struct runtime_config));
    
    // Default paths
    strncpy(rc->config_file_path, "/etc/cyrenus/cyrenus.conf", MAX_PATH_LEN - 1);
    strncpy(rc->database_path, "/var/lib/cyrenus/cyrenus.db", MAX_PATH_LEN - 1);
    strncpy(rc->geoip_db_path, "/var/lib/cyrenus/GeoLite2-Country.mmdb", MAX_PATH_LEN - 1);
    strncpy(rc->master_key_path, "/etc/cyrenus/master.key", MAX_PATH_LEN - 1);
    strncpy(rc->environment, "production", 31);
    
    // Default settings
    rc->http_port = 8181;
    strncpy(rc->username, "admin", MAX_STRING_LEN - 1);
    strncpy(rc->password, "admin", MAX_STRING_LEN - 1);
    rc->daemon_mode = false;
    rc->verbose = false;
    rc->debug = false;
    rc->no_geoip = false;
    rc->no_notifications = false;
    rc->dry_run = false;
    rc->log_level = 2;  // INFO

    // Default Attack Thresholds
    rc->syn_flood_rate = 1000;
    rc->udp_flood_rate = 100000; // Increased for modern QUIC/Video traffic
    rc->icmp_flood_rate = 100;
    rc->dns_amp_rate = 200;
    rc->max_frags = 15;
}

// Print usage information
void runtime_config_print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] [CONFIG_FILE]\n\n", program_name);
    printf("Cyrenus DDoS Protection System\n\n");
    printf("Options:\n");
    printf("  -i, --interface IFACE       Network interface to monitor\n");
    printf("  -p, --port PORT             HTTP API port (default: 8181)\n");
    printf("  -c, --config FILE           Configuration file path\n");
    printf("  -d, --database FILE         Database file path\n");
    printf("  -g, --geoip FILE            GeoIP database file path\n");
    printf("  -k, --key FILE              Master encryption key file path\n");
    printf("  -u, --username USER         Override admin username\n");
    printf("  -P, --password PASS         Override admin password (not recommended)\n");
    printf("  -D, --daemon                Run as daemon\n");
    printf("  -v, --verbose               Enable verbose output\n");
    printf("  -V, --debug                 Enable debug mode\n");
    printf("  -e, --environment ENV       Environment (development/production/testing)\n");
    printf("  -l, --log-level LEVEL       Log level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)\n");
    printf("  -L, --log-file FILE         Log file path\n");
    printf("  --no-geoip                  Disable GeoIP lookups\n");
    printf("  --no-notifications          Disable notifications\n");
    printf("  --dry-run                   Dry run mode (don't load eBPF programs)\n");
    printf("  -h, --help                  Display this help message\n");
    printf("  --version                   Display version information\n");
    printf("\nEnvironment Variables:\n");
    printf("  CYRENUS_INTERFACE           Network interface to monitor\n");
    printf("  CYRENUS_HTTP_PORT           HTTP API port\n");
    printf("  CYRENUS_CONFIG              Configuration file path\n");
    printf("  CYRENUS_DB_PATH             Database file path\n");
    printf("  CYRENUS_GEOIP_DB            GeoIP database file path\n");
    printf("  CYRENUS_MASTER_KEY          Master encryption key file path\n");
    printf("  CYRENUS_ENV                 Environment (development/production/testing)\n");
    printf("  CYRENUS_LOG_LEVEL           Log level (0-3)\n");
    printf("  CYRENUS_LOG_FILE            Log file path\n");
    printf("\nExamples:\n");
    printf("  %s                          # Use default config\n", program_name);
    printf("  %s -i eth0 -p 8080          # Override interface and port\n", program_name);
    printf("  %s -v -e development        # Verbose mode, development environment\n", program_name);
    printf("  %s /path/to/config.conf     # Use custom config file\n", program_name);
}

// Print version information
void runtime_config_print_version(void) {
    printf("Cyrenus DDoS Protection System v%s\n", CYRENUS_VERSION);
    printf("Build Date: %s\n", CYRENUS_BUILD_DATE);
    printf("eBPF-based network security and attack mitigation\n");
    printf("\nCopyright (c) 2025\n");
    printf("License: MIT\n");
}

// Parse command-line arguments
int runtime_config_parse_args(int argc, char **argv, struct runtime_config *rc) {
    static struct option long_options[] = {
        {"interface",       required_argument, 0, 'i'},
        {"port",            required_argument, 0, 'p'},
        {"config",          required_argument, 0, 'c'},
        {"database",        required_argument, 0, 'd'},
        {"geoip",           required_argument, 0, 'g'},
        {"key",             required_argument, 0, 'k'},
        {"username",        required_argument, 0, 'u'},
        {"password",        required_argument, 0, 'P'},
        {"daemon",          no_argument,       0, 'D'},
        {"verbose",         no_argument,       0, 'v'},
        {"debug",           no_argument,       0, 'V'},
        {"environment",     required_argument, 0, 'e'},
        {"log-level",       required_argument, 0, 'l'},
        {"log-file",        required_argument, 0, 'L'},
        {"no-geoip",        no_argument,       0, '1'},
        {"no-notifications",no_argument,       0, '2'},
        {"dry-run",         no_argument,       0, '3'},
        {"help",            no_argument,       0, 'h'},
        {"version",         no_argument,       0, '4'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "i:p:c:d:g:k:u:P:DvVe:l:L:h", 
                              long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(rc->interface, optarg, IFNAMSIZ - 1);
                break;
            case 'p':
                rc->http_port = (uint16_t)atoi(optarg);
                if (rc->http_port == 0) {
                    fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
                    return -1;
                }
                break;
            case 'c':
                strncpy(rc->config_file_path, optarg, MAX_PATH_LEN - 1);
                break;
            case 'd':
                strncpy(rc->database_path, optarg, MAX_PATH_LEN - 1);
                break;
            case 'g':
                strncpy(rc->geoip_db_path, optarg, MAX_PATH_LEN - 1);
                break;
            case 'k':
                strncpy(rc->master_key_path, optarg, MAX_PATH_LEN - 1);
                break;
            case 'u':
                strncpy(rc->username, optarg, MAX_STRING_LEN - 1);
                break;
            case 'P':
                strncpy(rc->password, optarg, MAX_STRING_LEN - 1);
                // Warn about insecure password passing
                fprintf(stderr, "Warning: Passing password via command line is insecure!\n");
                break;
            case 'D':
                rc->daemon_mode = true;
                break;
            case 'v':
                rc->verbose = true;
                rc->log_level = 2;  // INFO
                break;
            case 'V':
                rc->debug = true;
                rc->log_level = 3;  // DEBUG
                break;
            case 'e':
                strncpy(rc->environment, optarg, 31);
                break;
            case 'l':
                rc->log_level = atoi(optarg);
                if (rc->log_level < 0 || rc->log_level > 3) {
                    fprintf(stderr, "Error: Log level must be 0-3\n");
                    return -1;
                }
                break;
            case 'L':
                strncpy(rc->log_file, optarg, MAX_PATH_LEN - 1);
                break;
            case '1':
                rc->no_geoip = true;
                break;
            case '2':
                rc->no_notifications = true;
                break;
            case '3':
                rc->dry_run = true;
                break;
            case 'h':
                runtime_config_print_usage(argv[0]);
                exit(0);
            case '4':
                runtime_config_print_version();
                exit(0);
            default:
                runtime_config_print_usage(argv[0]);
                return -1;
        }
    }
    
    // If there's a positional argument, treat it as config file path
    if (optind < argc) {
        strncpy(rc->config_file_path, argv[optind], MAX_PATH_LEN - 1);
    }
    
    
    if (optind < argc) {
        strncpy(rc->config_file_path, argv[optind], MAX_PATH_LEN - 1);
    }
    
    return 0;
}

// Load configuration from file
int runtime_config_load_file(struct runtime_config *rc) {
    struct config file_cfg;
    memset(&file_cfg, 0, sizeof(struct config));
    
    if (load_config(rc->config_file_path, &file_cfg) != 0) {
        return -1;
    }
    
    // Copy values from file_cfg to rc
    if (strlen(file_cfg.interface) > 0)
        strncpy(rc->interface, file_cfg.interface, IFNAMSIZ - 1);
        
    if (file_cfg.http_port > 0)
        rc->http_port = (uint16_t)file_cfg.http_port;
        
    if (strlen(file_cfg.backend.url) > 0)
        strncpy(rc->backend_url, file_cfg.backend.url, MAX_URL_LEN - 1);
        
    if (strlen(file_cfg.backend.api_key) > 0)
        strncpy(rc->api_key, file_cfg.backend.api_key, 63);
        
    // Note: api_secret from backend isn't clearly mapped in runtime_config yet, 
    // assuming it might be needed later or is app_secret.
    
    if (strlen(file_cfg.app_secret) > 0)
        strncpy(rc->app_secret, file_cfg.app_secret, 63);

    if (strlen(file_cfg.username) > 0)
        strncpy(rc->username, file_cfg.username, MAX_STRING_LEN - 1);
        
    if (strlen(file_cfg.password) > 0)
        strncpy(rc->password, file_cfg.password, MAX_STRING_LEN - 1);

    // Load database path from config
    config_t conf;
    config_init(&conf);
    if (config_read_file(&conf, rc->config_file_path)) {
        const char *db_path = NULL;
        const char *geoip_path = NULL;
        
        // Load database path
        config_setting_t *database = config_lookup(&conf, "database");
        if (database != NULL) {
            if (config_setting_lookup_string(database, "path", &db_path)) {
                strncpy(rc->database_path, db_path, MAX_PATH_LEN - 1);
            }
        }
        
        // Load GeoIP path
        config_setting_t *geoip = config_lookup(&conf, "geoip");
        if (geoip != NULL) {
            if (config_setting_lookup_string(geoip, "database_path", &geoip_path)) {
                strncpy(rc->geoip_db_path, geoip_path, MAX_PATH_LEN - 1);
            }
        }
        
        config_destroy(&conf);
    }

    return 0;
}

// Load configuration from environment variables
void runtime_config_load_env(struct runtime_config *rc) {
    char *env_val;
    
    // Interface
    if ((env_val = getenv(ENV_CYRENUS_INTERFACE)) != NULL) {
        strncpy(rc->interface, env_val, IFNAMSIZ - 1);
    }
    
    // HTTP port
    if ((env_val = getenv(ENV_CYRENUS_HTTP_PORT)) != NULL) {
        rc->http_port = (uint16_t)atoi(env_val);
    }
    
    // Config file path
    if ((env_val = getenv(ENV_CYRENUS_CONFIG)) != NULL) {
        strncpy(rc->config_file_path, env_val, MAX_PATH_LEN - 1);
    }
    
    // Database path
    if ((env_val = getenv(ENV_CYRENUS_DB_PATH)) != NULL) {
        strncpy(rc->database_path, env_val, MAX_PATH_LEN - 1);
    }
    
    // GeoIP database path
    if ((env_val = getenv(ENV_CYRENUS_GEOIP_DB)) != NULL) {
        strncpy(rc->geoip_db_path, env_val, MAX_PATH_LEN - 1);
    }
    
    // Master key path
    if ((env_val = getenv(ENV_CYRENUS_MASTER_KEY)) != NULL) {
        strncpy(rc->master_key_path, env_val, MAX_PATH_LEN - 1);
    }
    
    // Environment
    if ((env_val = getenv(ENV_CYRENUS_ENV)) != NULL) {
        strncpy(rc->environment, env_val, 31);
    }
    
    // Log level
    if ((env_val = getenv(ENV_CYRENUS_LOG_LEVEL)) != NULL) {
        rc->log_level = atoi(env_val);
    }
    
    // Log file
    if ((env_val = getenv(ENV_CYRENUS_LOG_FILE)) != NULL) {
        strncpy(rc->log_file, env_val, MAX_PATH_LEN - 1);
    }
}

// Validate runtime configuration
int runtime_config_validate(const struct runtime_config *rc) {
    // Check interface is set
    if (strlen(rc->interface) == 0) {
        fprintf(stderr, "Error: Network interface not specified\n");
        return -1;
    }
    
    // Check port is valid
    if (rc->http_port == 0 || rc->http_port > 65535) {
        fprintf(stderr, "Error: Invalid HTTP port: %d\n", rc->http_port);
        return -1;
    }
    
    // Check config file exists
    if (access(rc->config_file_path, R_OK) != 0) {
        fprintf(stderr, "Warning: Config file not accessible: %s\n", rc->config_file_path);
    }
    
    // Check master key exists (required for encrypted database)
    if (access(rc->master_key_path, R_OK) != 0) {
        fprintf(stderr, "Warning: Master key file not accessible: %s\n", rc->master_key_path);
        fprintf(stderr, "Database encryption may not work properly\n");
    }
    
    // Validate environment
    if (strcmp(rc->environment, "development") != 0 &&
        strcmp(rc->environment, "production") != 0 &&
        strcmp(rc->environment, "testing") != 0) {
        fprintf(stderr, "Warning: Unknown environment '%s', using 'production'\n", rc->environment);
    }
    
    return 0;
}

// Print runtime configuration (for debugging)
void runtime_config_print(const struct runtime_config *rc) {
    printf("=== Runtime Configuration ===\n");
    printf("Interface:       %s\n", rc->interface);
    printf("HTTP Port:       %d\n", rc->http_port);
    printf("Config File:     %s\n", rc->config_file_path);
    printf("Database:        %s\n", rc->database_path);
    printf("GeoIP DB:        %s\n", rc->geoip_db_path);
    printf("Master Key:      %s\n", rc->master_key_path);
    printf("Environment:     %s\n", rc->environment);
    printf("Daemon Mode:     %s\n", rc->daemon_mode ? "yes" : "no");
    printf("Verbose:         %s\n", rc->verbose ? "yes" : "no");
    printf("Debug:           %s\n", rc->debug ? "yes" : "no");
    printf("Log Level:       %d\n", rc->log_level);
    if (strlen(rc->log_file) > 0) {
        printf("Log File:        %s\n", rc->log_file);
    }
    printf("GeoIP:           %s\n", rc->no_geoip ? "disabled" : "enabled");
    printf("Notifications:   %s\n", rc->no_notifications ? "disabled" : "enabled");
    printf("Dry Run:         %s\n", rc->dry_run ? "yes" : "no");
    printf("============================\n");
}
