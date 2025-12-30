#ifndef GEOIP_HELPERS_H
#define GEOIP_HELPERS_H

#include <maxminddb.h>

// Initialize global GeoIP database
int geoip_init(const char *db_path);

// Cleanup
void geoip_cleanup();

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

// Populate BPF map with GeoIP data
int geoip_populate_bpf_map(int map_fd);

#endif // GEOIP_HELPERS_H
