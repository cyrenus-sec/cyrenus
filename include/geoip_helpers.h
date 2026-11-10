#ifndef GEOIP_HELPERS_H
#define GEOIP_HELPERS_H

#include <maxminddb.h>

// Initialize global GeoIP database
int geoip_init(const char *db_path);

// Cleanup
void geoip_cleanup(void);

// data structure for return info
struct geoip_info {
    char country_code[3];
    char country_name[100];
    char city[100];
    double latitude;
    double longitude;
};

// Lookup IP
int geoip_lookup(const char *ip_str, struct geoip_info *info);

// Populate BPF maps with GeoIP data (IPv4 map and optional IPv6 map)
int geoip_populate_bpf_maps(int v4_map_fd, int v6_map_fd);
int geoip_populate_bpf_map(int map_fd);

#endif // GEOIP_HELPERS_H
