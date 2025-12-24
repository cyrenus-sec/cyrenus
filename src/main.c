#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "../include/config_handler.h"
#include "../include/bpf_loader.h"
#include "../include/http_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>


// Global running flag to control main loop
static int running = 1;

// Global interface pointer for cleanup
static const char *interface;


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

int main(int argc, char **argv) {
    // Check if the configuration file is provided
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load the configuration
    struct config cfg;
    if (load_config(argv[1], &cfg) != 0) {
        fprintf(stderr, "Failed to load configuration\n");
        return EXIT_FAILURE;
    }

    // Save interface from config for cleanup later
    interface = cfg.interface;

    // Print the loaded configuration for debugging purposes
    print_config(&cfg);

    // Variables to hold map file descriptors
    int map_fd_rules, map_fd_traffic, map_fd_host_ip , map_fd_udp_flood, map_fd_dns_track, map_fd_syn_flood ,  map_fd_attack_info_array,  map_fd_attack_count;

    uint32_t host_ip = get_interface_ip(cfg.interface);
    if (host_ip == 0) {
        fprintf(stderr, "Failed to get IP address for interface %s\n", cfg.interface);
        return EXIT_FAILURE;
    }
    printf("Detected host IP: %s\n", inet_ntoa((struct in_addr){host_ip}));

    // Load the BPF program
    if (load_bpf_program("build/xdp_prog.o", cfg.interface, host_ip,
                         &map_fd_rules, &map_fd_traffic, &map_fd_host_ip , &map_fd_udp_flood, &map_fd_dns_track, &map_fd_syn_flood , &map_fd_attack_info_array, &map_fd_attack_count) != 0) {
        fprintf(stderr, "Failed to load BPF program\n");
        return EXIT_FAILURE;
    }
    printf("DEBUG: map_fd_traffic = %d\n", map_fd_traffic);
    // Start the HTTP server
    struct MHD_Daemon *daemon = start_http_server(&cfg, map_fd_rules, map_fd_traffic, map_fd_udp_flood, map_fd_dns_track, map_fd_syn_flood ,   map_fd_attack_info_array,  map_fd_attack_count);
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        unload_bpf_program(cfg.interface);  // Clean up BPF program on failure
        return EXIT_FAILURE;
    }

    // Set up signal handlers to catch termination signals (SIGINT, SIGTERM)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Cyrenus is running. Press Ctrl+C to stop.\n");

    // Main loop: Keeps running until a termination signal is caught
    while (running) {
        sleep(1);
    }

    // Cleanup resources on termination
    stop_http_server(daemon);          // Stop HTTP server
    unload_bpf_program(interface);     // Unload the BPF program

    printf("Cyrenus has stopped.\n");

    return EXIT_SUCCESS;  // Exit with success
}
