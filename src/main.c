#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "../include/runtime_config.h"
#include "../include/database.h"
#include "../include/bpf_loader.h"
#include "../include/http_server.h"
#include "../include/http_server.h"
#include "../include/geoip_helpers.h"
#include "../include/websocket_server.h"
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/common.h"
#include "../include/saas_uplink.h"
#include "../include/api_handlers.h"
#include "../include/tetragon_events.h"

// Global running flag to control main loop
static int running = 1;

// Global structs for cleanup
static struct runtime_config config;
static struct database db;
struct database *g_db = NULL; // Global database for security API

uint32_t get_interface_ip(const char *interface_name) {
    int fd;
    struct ifreq ifr;
    uint32_t ip_addr = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Cannot create socket");
        return 0;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl error");
        close(fd);
        return 0;
    }

    close(fd);

    ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    return ip_addr;
}

// Signal handler to catch termination signals
void signal_handler(int signum) {
    printf("Caught signal %d, cleaning up...\n", signum);
    running = 0;  // Stop the main loop
}

struct monitor_ctx {
    int global_stats_fd;
};

// Monitor thread to poll stats and broadcast
void *monitor_thread(void *arg) {
    struct monitor_ctx *ctx = (struct monitor_ctx *)arg;
    uint32_t key = 0;
    int num_cpus = libbpf_num_possible_cpus();
    struct global_stats_t *values = malloc(sizeof(struct global_stats_t) * num_cpus);
    
    if (!values) {
        fprintf(stderr, "Failed to allocate memory for monitor values\n");
        free(ctx);
        return NULL;
    }
    
    uint64_t prev_packets = 0;
    uint64_t prev_bytes = 0;
    
    while (running) {
        if (!values) break;
        
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;
        
        if (ctx->global_stats_fd >= 0) {
            if (bpf_map_lookup_elem(ctx->global_stats_fd, &key, values) == 0) {
                for (int i = 0; i < num_cpus; i++) {
                    total_packets += values[i].total_packets;
                    total_bytes += values[i].total_bytes;
                }
            }
        }
        
        uint32_t pps = (prev_packets > 0) ? (uint32_t)(total_packets - prev_packets) : 0;
        uint64_t bps = (prev_bytes > 0) ? (total_bytes - prev_bytes) * 8 : 0;
        
        prev_packets = total_packets;
        prev_bytes = total_bytes;
        
        // Create JSON payload
        char msg[512];
        snprintf(msg, sizeof(msg), 
                 "{\"type\":\"traffic_update\",\"data\":{\"timestamp\":%ld,\"pps\":%u,\"bps\":%lu,\"total_packets\":%lu,\"total_bytes\":%lu}}", 
                 (long)time(NULL), pps, bps, total_packets, total_bytes);
                 
        ws_broadcast_message(msg);
        
        sleep(1); // 1Hz update
    }
    
    if (values) free(values);
    free(ctx);
    return NULL;
}

int main(int argc, char **argv) {
    // 1. Initialize and load runtime configuration
    runtime_config_init(&config);
    
    // Load environment variables first
    runtime_config_load_env(&config);
    
    // Parse command line arguments (can override env)
    if (runtime_config_parse_args(argc, argv, &config) != 0) {
        return EXIT_FAILURE;
    }

    // Load config file (using path from args/defaults)
    // NOTE: We load file values, then RE-APPLY args/env to ensure CLI overrides file
    if (access(config.config_file_path, R_OK) == 0) {
        printf("Loading configuration from %s...\n", config.config_file_path);
        if (runtime_config_load_file(&config) != 0) {
            fprintf(stderr, "Failed to load config file\n");
            return EXIT_FAILURE;
        }
        // Re-apply environment and args to override file values
        runtime_config_load_env(&config);
        runtime_config_parse_args(argc, argv, &config);
    } else {
        printf("Warning: Config file %s not found, using defaults/args\n", config.config_file_path);
    }
    
    // Validate configuration
    if (runtime_config_validate(&config) != 0) {
        return EXIT_FAILURE;
    }

    if (config.verbose) {
        runtime_config_print(&config);
    }

    // 2. Initialize and open database
    printf("Initializing database at %s...\n", config.database_path);
    if (database_init(&db, config.database_path, config.master_key_path) != 0) {
        fprintf(stderr, "Failed to initialize database\n");
        return EXIT_FAILURE;
    }

    if (database_open(&db) != 0) {
        fprintf(stderr, "Failed to open database\n");
        return EXIT_FAILURE;
    }

    // Create schema if needed
    if (database_create_schema(&db) != 0) {
        fprintf(stderr, "Failed to create database schema\n");
        database_close(&db);
        return EXIT_FAILURE;
    }

    // Initialize GeoIP if configured
    if (config.geoip_db_path && strlen(config.geoip_db_path) > 0 && access(config.geoip_db_path, F_OK) == 0) {
        if (geoip_init(config.geoip_db_path) != 0) {
             // Silently ignore if DB fails to open but exists (e.g. invalid format)
        } else {
            printf("GeoIP initialized with %s\n", config.geoip_db_path);
        }
    }

    // 3. Network Setup
    uint32_t host_ip = get_interface_ip(config.interface);
    if (host_ip == 0) {
        fprintf(stderr, "Failed to get IP address for interface %s\n", config.interface);
        database_close(&db);
        return EXIT_FAILURE;
    }
    printf("Detected host IP: %s\n", inet_ntoa((struct in_addr){host_ip}));

    // 4. Load eBPF Program
    // Variables to hold map file descriptors
    int map_fd_rules, map_fd_traffic, map_fd_host_ip, map_fd_udp_flood, map_fd_dns_track, 
        map_fd_syn_flood, map_fd_attack_info_array, map_fd_attack_count, map_fd_geoip, map_fd_blocked_countries, map_fd_global_stats, map_fd_config;

    if (!config.dry_run) {
        if (load_bpf_program("/usr/local/lib/cyrenus_xdp_prog.o", config.interface, host_ip,
                             &map_fd_rules, &map_fd_traffic, &map_fd_host_ip, 
                             &map_fd_udp_flood, &map_fd_dns_track, &map_fd_syn_flood, 
                             &map_fd_attack_info_array, &map_fd_attack_count,
                             &map_fd_geoip, &map_fd_blocked_countries, &map_fd_global_stats, &map_fd_config) != 0) {
            fprintf(stderr, "Failed to load BPF program\n");
            database_close(&db);
            return EXIT_FAILURE;
        }
    } else {
        printf("Dry run: BPF program loading skipped\n");
        // Mock FDs for dry run
        map_fd_traffic = -1;
    }

    // Populate GeoIP BPF map (if configured)
    if (!config.dry_run && config.geoip_db_path && strlen(config.geoip_db_path) > 0) {
        geoip_populate_bpf_map(map_fd_geoip);
    }

    // 5. Start HTTP Server
    struct MHD_Daemon *daemon = start_http_server(&config, &db, 
                                                 map_fd_rules, map_fd_traffic, 
                                                 map_fd_udp_flood, map_fd_dns_track, 
                                                 map_fd_syn_flood, map_fd_attack_info_array, 
                                                 map_fd_attack_count, map_fd_geoip, map_fd_blocked_countries, map_fd_global_stats, map_fd_config);
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server on port %d\n", config.http_port);
        if (!config.dry_run) unload_bpf_program(config.interface);
        database_close(&db);
        return EXIT_FAILURE;
    }

    // 6. Start WebSocket Server
    if (ws_server_init(&config) != 0) {
        fprintf(stderr, "Failed to start WebSocket server\n");
        // Proceeding anyway as HTTP is critical, WS is additive? 
        // Or fail? Let's log and continue for resilience.
    }
    
    pthread_t ws_thread_id;
    if (pthread_create(&ws_thread_id, NULL, ws_server_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create WebSocket thread\n");
    }

    // 7. Start Monitor Thread
    struct monitor_ctx *m_ctx = malloc(sizeof(struct monitor_ctx));
    if (m_ctx) {
        m_ctx->global_stats_fd = map_fd_global_stats;
        pthread_t monitor_tid;
        if (pthread_create(&monitor_tid, NULL, monitor_thread, m_ctx) != 0) {
            fprintf(stderr, "Failed to create monitor thread\n");
            free(m_ctx);
        } else {
            pthread_detach(monitor_tid);
        }
    }

    // 8. Start SaaS Uplink Thread
    struct saas_context *saas_ctx = malloc(sizeof(struct saas_context));
    // Pack FDs
    struct map_fds fds = {
        .rules_fd = map_fd_rules,
        .traffic_fd = map_fd_traffic,
        .udp_flood_fd = map_fd_udp_flood,
        .dns_track_fd = map_fd_dns_track,
        .syn_flood_fd = map_fd_syn_flood,
        .attack_info_array_fd = map_fd_attack_info_array,
        .attack_count_fd = map_fd_attack_count,
        .geoip_map_fd = map_fd_geoip,
        .blocked_countries_fd = map_fd_blocked_countries,
        .global_stats_fd = map_fd_global_stats,
        .config_map_fd = map_fd_config
    };
    
    if (saas_ctx) {
        // We need to pass a heap-allocated fds or ensure main stack stays valid (it does).
        // But saas_uplink uses pointer. We should probably copy it or malloc it if we want to be safe,
        // but passing address of stack struct in main() is safe as main() outlives threads.
        // Wait, saas_uplink_init stores pointer `ctx->fds = fds`.
        // If I pass `&fds` (stack), it is valid.
        
        // HOWEVER, `saas_ctx` requires `struct map_fds *`.
        // I will malloc one to be safe and clean.
        struct map_fds *fds_ptr = malloc(sizeof(struct map_fds));
        if (fds_ptr) {
            *fds_ptr = fds;
            saas_uplink_init(saas_ctx, &config, &db, fds_ptr);
            pthread_t saas_tid;
            if (pthread_create(&saas_tid, NULL, saas_uplink_thread, saas_ctx) != 0) {
                fprintf(stderr, "Failed to create SaaS thread\n");
            } else {
                pthread_detach(saas_tid);
            }
        }
    }

    // 9. Initialize and Start Tetragon Event Monitor
    printf("Initializing Tetragon event monitor...\\n");
    const char *tetragon_log_path = "/var/log/tetragon/tetragon.log";
    
    if (tetragon_init(tetragon_log_path) == 0) {
        printf("Tetragon monitor initialized for: %s\\n", tetragon_log_path);
        
        // Set global database pointer for security API
        g_db = &db;
        
        if (tetragon_start_monitor() == 0) {
            printf("Tetragon event monitor started successfully\\n");
        } else {
            fprintf(stderr, "Warning: Failed to start Tetragon monitor thread\\n");
        }
    } else {
        fprintf(stderr, "Warning: Failed to initialize Tetragon monitor\\n");
        fprintf(stderr, "Security event monitoring will not be available.\\n");
        fprintf(stderr, "Make sure Tetragon is installed and running.\\n");
    }

    // Set up signal handlers to catch termination signals (SIGINT, SIGTERM)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Cyrenus is running on %s:%d. Press Ctrl+C to stop.\n", 
           inet_ntoa((struct in_addr){host_ip}), config.http_port);

    // Main loop: Keeps running until a termination signal is caught
    while (running) {
        sleep(1);
        // Here we could add periodic tasks like cleaning up old database records
        // or syncing eBPF maps to database
    }

    // Cleanup resources on termination
    printf("Stopping HTTP server...\n");
    stop_http_server(daemon);
    
    printf("Stopping WebSocket server...\n");
    ws_server_cleanup();
    // Join thread? For now detaching or letting it die with process is acceptable, 
    // but cleaner is to join. (Skipping join code for brevity unless critical)
    
    if (!config.dry_run) {
        printf("Unloading BPF program...\n");
        unload_bpf_program(config.interface);
    }
    
    printf("Closing database...\n");
    database_close(&db);

    printf("Cyrenus has stopped.\n");

    return EXIT_SUCCESS;
}
