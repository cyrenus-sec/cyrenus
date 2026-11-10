#include "api_handlers.h"
#include "../include/database.h"
#include "../include/tetragon_events.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <json-c/json.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

// External global database
extern struct database *g_db;

#define DEPLOYED_POLICY_DIR "/etc/tetragon/policies"
#define TETRAGON_CONFIG_PATH "/etc/tetragon/tetragon.yaml"
#define TETRAGON_LOG_PATH "/var/log/tetragon/tetragon.log"
#define MAX_POLICY_FILE_BYTES (4 * 1024 * 1024)

// Resolve policy template directory: CYRENUS_POLICY_DIR -> ./config/tetragon/policies -> /etc/tetragon/policies
static const char *get_policy_dir(void) {
    struct stat st;
    const char *env_dir = getenv("CYRENUS_POLICY_DIR");
    if (env_dir && env_dir[0] != '\0' && stat(env_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        return env_dir;
    }
    if (stat("./config/tetragon/policies", &st) == 0 && S_ISDIR(st.st_mode)) {
        return "./config/tetragon/policies";
    }
    return DEPLOYED_POLICY_DIR;
}

// Strict policy name validation: [A-Za-z0-9_-]{1,128} (no slashes, "..", or shell metacharacters)
static int is_valid_policy_name(const char *name) {
    if (!name || name[0] == '\0') return 0;
    size_t len = 0;
    for (const char *p = name; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (!isalnum(c) && c != '_' && c != '-') {
            return 0;
        }
        if (++len > 128) return 0;
    }
    return 1;
}

// Safe file copy without shell invocation
static int copy_file_safe(const char *src, const char *dst) {
    struct stat st_src, st_dst;
    if (stat(src, &st_src) != 0) return -1;
    if (stat(dst, &st_dst) == 0 &&
        st_src.st_dev == st_dst.st_dev &&
        st_src.st_ino == st_dst.st_ino) {
        return 0; // Same underlying file, nothing to copy
    }

    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    char buf[8192];
    size_t n;
    int err = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            err = -1;
            break;
        }
    }
    if (ferror(in)) err = -1;

    fclose(in);
    if (fclose(out) != 0) err = -1;
    if (err == 0) chmod(dst, 0644);
    return err;
}

// Execute command without /bin/sh
static int run_cmd_no_shell(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int restart_tetragon_service(void) {
    if (geteuid() == 0) {
        char *const argv[] = {"systemctl", "restart", "tetragon", NULL};
        return run_cmd_no_shell(argv);
    }
    char *const argv[] = {"sudo", "-n", "systemctl", "restart", "tetragon", NULL};
    return run_cmd_no_shell(argv);
}

// API: GET /api/security/events
// Query parameters: severity, event_type, from, to, limit, offset
struct MHD_Response *api_security_events_list(struct MHD_Connection *connection,
                                               const char *method,
                                               const char *url) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    // Parse query parameters
    const char *severity_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "severity");
    const char *event_type = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "event_type");
    const char *from_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "from");
    const char *to_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "to");
    const char *limit_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
    const char *offset_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "offset");
    
    int severity_min = severity_str ? atoi(severity_str) : 0;
    
    // Convert to nanoseconds (DB uses nanoseconds)
    // Default 'to' is current time
    // If input is small (likely seconds/millis), convert to nanoseconds
    time_t from_val = from_str ? atoll(from_str) : 0;
    time_t to_val = to_str ? atoll(to_str) : time(NULL);
    
    // Heuristic: if time is < 3000000000 (year 2065), it's seconds
    // If it's < 3000000000000, it's milliseconds
    // Otherwise it's nanoseconds
    
    if (from_val > 0 && from_val < 3000000000LL) from_val *= 1000000000LL;
    else if (from_val > 0 && from_val < 3000000000000LL) from_val *= 1000000LL;
    
    if (to_val > 0 && to_val < 3000000000LL) to_val *= 1000000000LL;
    else if (to_val > 0 && to_val < 3000000000000LL) to_val *= 1000000LL;
    
    time_t from = from_val;
    time_t to = to_val;
    
    int limit = limit_str ? atoi(limit_str) : 100;
    int offset = offset_str ? atoi(offset_str) : 0;
    
    // Fetch events from database
    struct security_event_record *events = NULL;
    int count = 0;
    
    if (database_list_security_events(g_db, &events, &count, severity_min, 
                                       event_type, from, to, limit, offset) != 0) {
        return create_json_response(500, "{\"error\":\"Failed to fetch security events\"}");
    }
    
    // Build JSON response
    struct json_object *response = json_object_new_object();
    struct json_object *events_array = json_object_new_array();
    
    for (int i = 0; i < count; i++) {
        struct json_object *event_obj = json_object_new_object();
        
        json_object_object_add(event_obj, "id", json_object_new_int64(events[i].id));
        json_object_object_add(event_obj, "timestamp", json_object_new_int64(events[i].timestamp));
        json_object_object_add(event_obj, "event_type", json_object_new_string(events[i].event_type));
        json_object_object_add(event_obj, "severity", json_object_new_int(events[i].severity));
        json_object_object_add(event_obj, "process_name", json_object_new_string(events[i].process_name));
        json_object_object_add(event_obj, "pid", json_object_new_int(events[i].pid));
        json_object_object_add(event_obj, "ppid", json_object_new_int(events[i].ppid));
        json_object_object_add(event_obj, "command", json_object_new_string(events[i].command));
        json_object_object_add(event_obj, "binary_path", json_object_new_string(events[i].binary_path));
        json_object_object_add(event_obj, "parent_binary", json_object_new_string(events[i].parent_binary));
        json_object_object_add(event_obj, "action", json_object_new_string(events[i].action));
        json_object_object_add(event_obj, "policy_name", json_object_new_string(events[i].policy_name));
        
        if (events[i].src_ip[0]) {
            json_object_object_add(event_obj, "src_ip", json_object_new_string(events[i].src_ip));
        }
        if (events[i].file_path[0]) {
            json_object_object_add(event_obj, "file_path", json_object_new_string(events[i].file_path));
        }
        
        json_object_array_add(events_array, event_obj);
    }
    
    json_object_object_add(response, "events", events_array);
    json_object_object_add(response, "total", json_object_new_int(count));
    json_object_object_add(response, "limit", json_object_new_int(limit));
    json_object_object_add(response, "offset", json_object_new_int(offset));
    
    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = create_json_response(200, json_str);
    
    json_object_put(response);
    database_free_security_event_list(events, count);
    
    return mhd_response;
}

// API: GET /api/security/stats
struct MHD_Response *api_security_stats(struct MHD_Connection *connection,
                                        const char *method,
                                        const char *url) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    const char *from_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "from");
    const char *to_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "to");
    
    time_t from_val = from_str ? atoll(from_str) : time(NULL) - 86400; // Last 24h default
    time_t to_val = to_str ? atoll(to_str) : time(NULL);
    
    // Apply same heuristic as events list to ensure DB (nanoseconds) matches query
    if (from_val > 0 && from_val < 3000000000LL) from_val *= 1000000000LL;
    else if (from_val > 0 && from_val < 3000000000000LL) from_val *= 1000000LL;
    
    if (to_val > 0 && to_val < 3000000000LL) to_val *= 1000000000LL;
    else if (to_val > 0 && to_val < 3000000000000LL) to_val *= 1000000LL;
    
    time_t from = from_val;
    time_t to = to_val;
    
    int total_events = 0, critical_alerts = 0, events_blocked = 0;
    
    if (database_get_security_stats(g_db, from, to, &total_events, 
                                     &critical_alerts, &events_blocked) != 0) {
        return create_json_response(500, "{\"error\":\"Failed to fetch stats\"}");
    }
    
    // Get Tetragon runtime stats
    struct tetragon_stats tg_stats;
    tetragon_get_stats(&tg_stats);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "total_events", json_object_new_int(total_events));
    json_object_object_add(response, "critical_alerts", json_object_new_int(critical_alerts));
    json_object_object_add(response, "events_blocked", json_object_new_int(events_blocked));
    json_object_object_add(response, "process_exec_events", json_object_new_int64(tg_stats.process_exec_events));
    json_object_object_add(response, "alerts_generated", json_object_new_int64(tg_stats.alerts_generated));
    json_object_object_add(response, "tetragon_running", json_object_new_boolean(tetragon_is_running()));
    
    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = create_json_response(200, json_str);
    
    json_object_put(response);
    return mhd_response;
}

// API: GET /api/security/policies
struct MHD_Response *api_security_policies_list(struct MHD_Connection *connection,
                                                const char *method,
                                                const char *url) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    struct json_object *response = json_object_new_object();
    struct json_object *policies_array = json_object_new_array();
    
    // Read policies from directory
    const char *policy_dir = get_policy_dir();
    DIR *dir = opendir(policy_dir);
    
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            size_t dlen = strlen(entry->d_name);
            if (dlen > 5 && strcmp(entry->d_name + dlen - 5, ".yaml") == 0) {
                struct json_object *policy_obj = json_object_new_object();
                
                // Extract policy name from filename
                char name[256] = {0};
                strncpy(name, entry->d_name, sizeof(name) - 1);
                char *dot = strrchr(name, '.');
                if (dot) *dot = '\0';
                
                json_object_object_add(policy_obj, "name", json_object_new_string(name));
                json_object_object_add(policy_obj, "filename", json_object_new_string(entry->d_name));
                
                // Check if policy is deployed
                char deployed_path[512];
                snprintf(deployed_path, sizeof(deployed_path), "%s/%s", DEPLOYED_POLICY_DIR, entry->d_name);
                json_object_object_add(policy_obj, "deployed", json_object_new_boolean(access(deployed_path, F_OK) == 0));
                
                // Get file stats
                char full_path[512];
                snprintf(full_path, sizeof(full_path), "%s/%s", policy_dir, entry->d_name);
                struct stat st;
                if (stat(full_path, &st) == 0) {
                    json_object_object_add(policy_obj, "size", json_object_new_int64(st.st_size));
                    json_object_object_add(policy_obj, "modified", json_object_new_int64(st.st_mtime));
                }
                
                json_object_array_add(policies_array, policy_obj);
            }
        }
        closedir(dir);
    }
    
    json_object_object_add(response, "policies", policies_array);
    
    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = create_json_response(200, json_str);
    
    json_object_put(response);
    return mhd_response;
}

// API: GET /api/security/policy/:name
struct MHD_Response *api_security_policy_get(struct MHD_Connection *connection,
                                             const char *method,
                                             const char *url,
                                             const char *policy_name) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }

    if (!is_valid_policy_name(policy_name)) {
        return create_json_response(400, "{\"error\":\"Invalid policy name\"}");
    }
    
    // Build file path
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s.yaml", get_policy_dir(), policy_name);
    
    // Read file
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        return create_json_response(404, "{\"error\":\"Policy not found\"}");
    }
    
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return create_json_response(500, "{\"error\":\"Failed to seek policy file\"}");
    }
    long size = ftell(fp);
    if (size < 0 || size > MAX_POLICY_FILE_BYTES) {
        fclose(fp);
        return create_json_response(500, "{\"error\":\"Invalid policy file size\"}");
    }
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc((size_t)size + 1);
    if (!content) {
        fclose(fp);
        return create_json_response(500, "{\"error\":\"Out of memory\"}");
    }
    size_t read_bytes = fread(content, 1, (size_t)size, fp);
    content[read_bytes] = '\0';
    fclose(fp);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "name", json_object_new_string(policy_name));
    json_object_object_add(response, "content", json_object_new_string(content));
    
    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = create_json_response(200, json_str);
    
    json_object_put(response);
    free(content);
    return mhd_response;
}

// API: POST /api/security/policy/:name
struct MHD_Response *api_security_policy_save(struct MHD_Connection *connection,
                                              const char *method,
                                              const char *policy_name,
                                              const char *upload_data,
                                              size_t upload_data_size) {
    if (strcmp(method, "POST") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }

    if (!is_valid_policy_name(policy_name)) {
        return create_json_response(400, "{\"error\":\"Invalid policy name\"}");
    }
    
    if (!upload_data || upload_data_size == 0) {
        return create_json_response(400, "{\"error\":\"No content provided\"}");
    }
    
    // Parse JSON
    struct json_object *json = json_tokener_parse(upload_data);
    if (!json) {
        return create_json_response(400, "{\"error\":\"Invalid JSON\"}");
    }
    
    struct json_object *content_obj;
    if (!json_object_object_get_ex(json, "content", &content_obj)) {
        json_object_put(json);
        return create_json_response(400, "{\"error\":\"Missing content field\"}");
    }
    
    const char *content = json_object_get_string(content_obj);
    if (!content) {
        json_object_put(json);
        return create_json_response(400, "{\"error\":\"Invalid content field\"}");
    }
    
    // Write to file
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s.yaml", get_policy_dir(), policy_name);
    
    FILE *fp = fopen(file_path, "w");
    if (!fp) {
        json_object_put(json);
        return create_json_response(500, "{\"error\":\"Failed to write policy file\"}");
    }
    
    fprintf(fp, "%s", content);
    fclose(fp);
    json_object_put(json);
    
    return create_json_response(200, "{\"success\":true,\"message\":\"Policy saved\"}");
}

// API: POST /api/security/policy/:name/deploy
struct MHD_Response *api_security_policy_deploy(struct MHD_Connection *connection,
                                                const char *method,
                                                const char *policy_name) {
    if (strcmp(method, "POST") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }

    if (!is_valid_policy_name(policy_name)) {
        return create_json_response(400, "{\"error\":\"Invalid policy name\"}");
    }
    
    // Copy policy to Tetragon directory
    char src[512], dst[512];
    snprintf(src, sizeof(src), "%s/%s.yaml", get_policy_dir(), policy_name);
    snprintf(dst, sizeof(dst), "%s/%s.yaml", DEPLOYED_POLICY_DIR, policy_name);

    mkdir(DEPLOYED_POLICY_DIR, 0755);

    if (copy_file_safe(src, dst) != 0) {
        return create_json_response(500, "{\"error\":\"Failed to deploy policy file\"}");
    }
    
    int result = restart_tetragon_service();
    
    if (result == 0) {
        return create_json_response(200, "{\"success\":true,\"message\":\"Policy deployed and Tetragon restarted\"}");
    } else {
        return create_json_response(200, "{\"success\":true,\"message\":\"Policy deployed (Tetragon service restart unavailable)\"}");
    }
}

// API: DELETE /api/security/policy/:name
struct MHD_Response *api_security_policy_delete(struct MHD_Connection *connection,
                                                const char *method,
                                                const char *policy_name) {
    if (strcmp(method, "DELETE") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }

    if (!is_valid_policy_name(policy_name)) {
        return create_json_response(400, "{\"error\":\"Invalid policy name\"}");
    }
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s.yaml", get_policy_dir(), policy_name);
    
    if (unlink(file_path) == 0) {
        // Also remove from deployed location
        char deployed_path[512];
        snprintf(deployed_path, sizeof(deployed_path), "%s/%s.yaml", DEPLOYED_POLICY_DIR, policy_name);
        unlink(deployed_path); // Ignore error if not deployed or same file
        
        restart_tetragon_service();
        
        return create_json_response(200, "{\"success\":true,\"message\":\"Policy deleted\"}");
    } else {
        return create_json_response(404, "{\"error\":\"Failed to delete policy\"}");
    }
}

// API: GET /api/security/logs
// Stream Tetragon logs (pure C tail without popen)
struct MHD_Response *api_security_logs(struct MHD_Connection *connection,
                                       const char *method,
                                       const char *url) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    const char *lines_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "lines");
    int lines = lines_str ? atoi(lines_str) : 100;
    if (lines <= 0) lines = 100;
    if (lines > 5000) lines = 5000;
    
    struct json_object *response = json_object_new_object();
    struct json_object *logs_array = json_object_new_array();

    FILE *fp = fopen(TETRAGON_LOG_PATH, "r");
    if (fp) {
        char **ring = calloc((size_t)lines, sizeof(char *));
        if (ring) {
            int count = 0;
            char line[8192];
            while (fgets(line, sizeof(line), fp)) {
                int idx = count % lines;
                free(ring[idx]);
                ring[idx] = strdup(line);
                count++;
            }
            int start = (count > lines) ? (count - lines) : 0;
            for (int i = start; i < count; i++) {
                char *entry = ring[i % lines];
                if (entry) {
                    struct json_object *log_obj = json_tokener_parse(entry);
                    if (log_obj) {
                        json_object_array_add(logs_array, log_obj);
                    }
                }
            }
            for (int i = 0; i < lines; i++) {
                free(ring[i]);
            }
            free(ring);
        }
        fclose(fp);
    }
    
    json_object_object_add(response, "logs", logs_array);
    json_object_object_add(response, "count", json_object_new_int(json_object_array_length(logs_array)));
    
    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = create_json_response(200, json_str);
    
    json_object_put(response);
    return mhd_response;
}

// API: GET /api/security/config
struct MHD_Response *api_security_config_get(struct MHD_Connection *connection,
                                             const char *method,
                                             const char *url) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    // Read Tetragon config
    FILE *fp = fopen(TETRAGON_CONFIG_PATH, "rb");
    if (!fp) {
        return create_json_response(404, "{\"error\":\"Config file not found\"}");
    }
    
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return create_json_response(500, "{\"error\":\"Failed to read config file\"}");
    }
    long size = ftell(fp);
    if (size < 0 || size > MAX_POLICY_FILE_BYTES) {
        fclose(fp);
        return create_json_response(500, "{\"error\":\"Invalid config file size\"}");
    }
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc((size_t)size + 1);
    if (!content) {
        fclose(fp);
        return create_json_response(500, "{\"error\":\"Out of memory\"}");
    }
    size_t read_bytes = fread(content, 1, (size_t)size, fp);
    content[read_bytes] = '\0';
    fclose(fp);
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "content", json_object_new_string(content));
    
    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = create_json_response(200, json_str);
    
    json_object_put(response);
    free(content);
    return mhd_response;
}

// API: POST /api/security/config
struct MHD_Response *api_security_config_save(struct MHD_Connection *connection,
                                              const char *method,
                                              const char *upload_data,
                                              size_t upload_data_size) {
    if (strcmp(method, "POST") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    if (!upload_data || upload_data_size == 0) {
        return create_json_response(400, "{\"error\":\"No content provided\"}");
    }
    
    // Parse JSON
    struct json_object *json = json_tokener_parse(upload_data);
    if (!json) {
        return create_json_response(400, "{\"error\":\"Invalid JSON\"}");
    }
    
    struct json_object *content_obj;
    if (!json_object_object_get_ex(json, "content", &content_obj)) {
        json_object_put(json);
        return create_json_response(400, "{\"error\":\"Missing content field\"}");
    }
    
    const char *content = json_object_get_string(content_obj);
    if (!content) {
        json_object_put(json);
        return create_json_response(400, "{\"error\":\"Invalid content field\"}");
    }
    
    // Atomic write to Tetragon config without predictable /tmp path
    char tmp_path[] = "/etc/tetragon/.tetragon.yaml.XXXXXX";
    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd < 0) {
        json_object_put(json);
        return create_json_response(500, "{\"error\":\"Failed to create config temp file\"}");
    }
    
    FILE *fp = fdopen(tmp_fd, "w");
    if (!fp) {
        close(tmp_fd);
        unlink(tmp_path);
        json_object_put(json);
        return create_json_response(500, "{\"error\":\"Failed to write config\"}");
    }
    
    fprintf(fp, "%s", content);
    fclose(fp);
    chmod(tmp_path, 0644);
    
    if (rename(tmp_path, TETRAGON_CONFIG_PATH) != 0) {
        unlink(tmp_path);
        json_object_put(json);
        return create_json_response(500, "{\"error\":\"Failed to replace configuration\"}");
    }
    json_object_put(json);
    
    restart_tetragon_service();
    return create_json_response(200, "{\"success\":true,\"message\":\"Configuration saved\"}");
}
