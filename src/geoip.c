#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <maxminddb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "../include/geoip_helpers.h"
#include "../include/common.h"

static MMDB_s mmdb;
static int db_open = 0;

static void copy_mmdb_utf8(const MMDB_entry_data_s *data, char *dst, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    dst[0] = '\0';
    if (!data || !data->has_data || data->type != MMDB_DATA_TYPE_UTF8_STRING || !data->utf8_string) {
        return;
    }
    size_t len = data->data_size < dst_size - 1 ? data->data_size : dst_size - 1;
    memcpy(dst, data->utf8_string, len);
    dst[len] = '\0';
}

int geoip_init(const char *db_path) {
    if (!db_path || db_path[0] == '\0') return -1;
    if (db_open) return 0;

    int status = MMDB_open(db_path, MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Cannot open MMDB %s: %s\n", db_path, MMDB_strerror(status));
        return -1;
    }

    db_open = 1;
    return 0;
}

void geoip_cleanup() {
    if (db_open) {
        MMDB_close(&mmdb);
        db_open = 0;
    }
}

int geoip_lookup(const char *ip_str, struct geoip_info *info) {
    if (!db_open || !ip_str || !info) return -1;

    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip_str, &gai_error, &mmdb_error);

    if (gai_error != 0) {
        fprintf(stderr, "Error from getaddrinfo for %s - %s\n", ip_str, gai_strerror(gai_error));
        return -1;
    }

    if (mmdb_error != MMDB_SUCCESS) {
        fprintf(stderr, "Got an error from libmaxminddb: %s\n", MMDB_strerror(mmdb_error));
        return -1;
    }

    if (!result.found_entry) {
        return -1;
    }

    memset(info, 0, sizeof(struct geoip_info));
    MMDB_entry_data_s entry_data;

    if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS) {
        copy_mmdb_utf8(&entry_data, info->country_code, sizeof(info->country_code));
    }

    if (MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS) {
        copy_mmdb_utf8(&entry_data, info->country_name, sizeof(info->country_name));
    }

    if (MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL) == MMDB_SUCCESS) {
        copy_mmdb_utf8(&entry_data, info->city, sizeof(info->city));
    }

    return 0;
}

struct geoip_walk_stats {
    int map_fd;
    uint32_t skip_node;
    uint64_t inserted;
    uint64_t errors;
};

static int extract_country_code(MMDB_entry_s *entry, uint16_t *cc_out) {
    MMDB_entry_data_s entry_data;
    if (MMDB_get_value(entry, &entry_data, "country", "iso_code", NULL) != MMDB_SUCCESS ||
        !entry_data.has_data ||
        entry_data.type != MMDB_DATA_TYPE_UTF8_STRING ||
        entry_data.data_size < 2) {
        return -1;
    }

    *cc_out = (uint16_t)(((unsigned char)entry_data.utf8_string[0] << 8) |
                         (unsigned char)entry_data.utf8_string[1]);
    return 0;
}

static void insert_geoip_cidr(struct geoip_walk_stats *st, uint32_t ip_host, uint32_t prefixlen, MMDB_entry_s *entry) {
    uint16_t cc = 0;
    if (extract_country_code(entry, &cc) != 0) return;

    struct geoip_key key = {
        .prefixlen = prefixlen,
        .ip = htonl(ip_host)
    };

    if (bpf_map_update_elem(st->map_fd, &key, &cc, BPF_ANY) == 0) {
        st->inserted++;
    } else {
        st->errors++;
    }
}

static void insert_geoip6_cidr(struct geoip_walk_stats *st, const uint8_t ip_bytes[16], uint32_t prefixlen, MMDB_entry_s *entry) {
    uint16_t cc = 0;
    if (extract_country_code(entry, &cc) != 0) return;

    struct geoip6_key key = { .prefixlen = prefixlen };
    memcpy(key.ip, ip_bytes, 16);

    if (bpf_map_update_elem(st->map_fd, &key, &cc, BPF_ANY) == 0) {
        st->inserted++;
    } else {
        st->errors++;
    }
}

static void walk_ipv4_tree(struct geoip_walk_stats *st, uint32_t node_num, uint32_t cur_ip, uint32_t depth) {
    if (depth >= 32 || node_num >= mmdb.metadata.node_count) {
        return;
    }

    MMDB_search_node_s node;
    if (MMDB_read_node(&mmdb, node_num, &node) != MMDB_SUCCESS) {
        st->errors++;
        return;
    }

    uint32_t bit_mask = 1U << (31 - depth);
    uint32_t next_prefixlen = depth + 1;

    // Left branch (bit = 0)
    if (node.left_record_type == MMDB_RECORD_TYPE_SEARCH_NODE) {
        walk_ipv4_tree(st, (uint32_t)node.left_record, cur_ip, depth + 1);
    } else if (node.left_record_type == MMDB_RECORD_TYPE_DATA) {
        MMDB_entry_s entry = node.left_record_entry;
        insert_geoip_cidr(st, cur_ip, next_prefixlen, &entry);
    }

    // Right branch (bit = 1)
    uint32_t right_ip = cur_ip | bit_mask;
    if (node.right_record_type == MMDB_RECORD_TYPE_SEARCH_NODE) {
        walk_ipv4_tree(st, (uint32_t)node.right_record, right_ip, depth + 1);
    } else if (node.right_record_type == MMDB_RECORD_TYPE_DATA) {
        MMDB_entry_s entry = node.right_record_entry;
        insert_geoip_cidr(st, right_ip, next_prefixlen, &entry);
    }
}

static void walk_ipv6_tree(struct geoip_walk_stats *st, uint32_t node_num, const uint8_t cur_ip[16], uint32_t depth) {
    if (depth >= 128 || node_num >= mmdb.metadata.node_count) {
        return;
    }
    if (st->skip_node != 0 && node_num == st->skip_node) {
        return;
    }

    MMDB_search_node_s node;
    if (MMDB_read_node(&mmdb, node_num, &node) != MMDB_SUCCESS) {
        st->errors++;
        return;
    }

    uint32_t next_prefixlen = depth + 1;

    // Left branch (bit = 0)
    if (node.left_record_type == MMDB_RECORD_TYPE_SEARCH_NODE) {
        walk_ipv6_tree(st, (uint32_t)node.left_record, cur_ip, depth + 1);
    } else if (node.left_record_type == MMDB_RECORD_TYPE_DATA) {
        MMDB_entry_s entry = node.left_record_entry;
        insert_geoip6_cidr(st, cur_ip, next_prefixlen, &entry);
    }

    // Right branch (bit = 1)
    uint8_t right_ip[16];
    memcpy(right_ip, cur_ip, 16);
    right_ip[depth / 8] |= (uint8_t)(1U << (7 - (depth % 8)));

    if (node.right_record_type == MMDB_RECORD_TYPE_SEARCH_NODE) {
        walk_ipv6_tree(st, (uint32_t)node.right_record, right_ip, depth + 1);
    } else if (node.right_record_type == MMDB_RECORD_TYPE_DATA) {
        MMDB_entry_s entry = node.right_record_entry;
        insert_geoip6_cidr(st, right_ip, next_prefixlen, &entry);
    }
}

int geoip_populate_bpf_maps(int v4_map_fd, int v6_map_fd) {
    if (!db_open || (v4_map_fd < 0 && v6_map_fd < 0)) return -1;

    // Ensure libmaxminddb has resolved ipv4_start_node for IPv6 hybrid DBs
    if (mmdb.metadata.ip_version == 6 && mmdb.ipv4_start_node.node_value == 0 && mmdb.ipv4_start_node.netmask == 0) {
        int gai_err = 0, mmdb_err = 0;
        MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_err, &mmdb_err);
    }

    int overall_ok = 0;

    if (v4_map_fd >= 0) {
        uint32_t start_node = 0;
        uint32_t start_depth = 0;

        if (mmdb.metadata.ip_version == 6) {
            start_node = mmdb.ipv4_start_node.node_value;
            if (mmdb.ipv4_start_node.netmask > 96) {
                start_depth = (uint32_t)(mmdb.ipv4_start_node.netmask - 96);
            }
        }

        printf("Populating eBPF GeoIP IPv4 map (IPv%u tree, start_node=%u)...\n",
               mmdb.metadata.ip_version, start_node);

        struct geoip_walk_stats st4 = {
            .map_fd = v4_map_fd,
            .skip_node = 0,
            .inserted = 0,
            .errors = 0
        };

        if (start_node < mmdb.metadata.node_count) {
            walk_ipv4_tree(&st4, start_node, 0, start_depth);
        }

        printf("GeoIP BPF map populated: %llu IPv4 CIDRs inserted (%llu errors).\n",
               (unsigned long long)st4.inserted, (unsigned long long)st4.errors);
        if (st4.inserted == 0 && st4.errors > 0) overall_ok = -1;
    }

    if (v6_map_fd >= 0 && mmdb.metadata.ip_version == 6) {
        struct geoip_walk_stats st6 = {
            .map_fd = v6_map_fd,
            .skip_node = mmdb.ipv4_start_node.node_value,
            .inserted = 0,
            .errors = 0
        };
        uint8_t zero_ip[16] = {0};

        if (mmdb.metadata.node_count > 0) {
            walk_ipv6_tree(&st6, 0, zero_ip, 0);
        }

        printf("GeoIP6 BPF map populated: %llu IPv6 CIDRs inserted (%llu errors).\n",
               (unsigned long long)st6.inserted, (unsigned long long)st6.errors);
        if (st6.inserted == 0 && st6.errors > 0) overall_ok = -1;
    }

    return overall_ok;
}

int geoip_populate_bpf_map(int map_fd) {
    return geoip_populate_bpf_maps(map_fd, -1);
}
