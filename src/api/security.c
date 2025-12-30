#include "api_handlers.h"
#include "../include/database.h"
#include "../include/tetragon_events.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

// External global database
extern struct database *g_db;

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
    const char *policy_dir = "/home/moh/Documents/cyrenus/config/tetragon/policies";
    DIR *dir = opendir(policy_dir);
    
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, ".yaml")) {
                struct json_object *policy_obj = json_object_new_object();
                
                // Extract policy name from filename
                char name[256];
                strncpy(name, entry->d_name, sizeof(name) - 1);
                char *dot = strrchr(name, '.');
                if (dot) *dot = '\0';
                
                json_object_object_add(policy_obj, "name", json_object_new_string(name));
                json_object_object_add(policy_obj, "filename", json_object_new_string(entry->d_name));
                
                // Check if policy is deployed
                char deployed_path[512];
                snprintf(deployed_path, sizeof(deployed_path), "/etc/tetragon/policies/%s", entry->d_name);
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
    
    // Build file path
    char file_path[512];
    snprintf(file_path, sizeof(file_path), 
             "/home/moh/Documents/cyrenus/config/tetragon/policies/%s.yaml", policy_name);
    
    // Read file
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        return create_json_response(404, "{\"error\":\"Policy not found\"}");
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    fread(content, 1, size, fp);
    content[size] = '\0';
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
    
    // Write to file
    char file_path[512];
    snprintf(file_path, sizeof(file_path),
             "/home/moh/Documents/cyrenus/config/tetragon/policies/%s.yaml", policy_name);
    
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
    
    // Copy policy to Tetragon directory
    char src[512], dst[512], cmd[2048];
    snprintf(src, sizeof(src), "/home/moh/Documents/cyrenus/config/tetragon/policies/%s.yaml", policy_name);
    snprintf(dst, sizeof(dst), "/etc/tetragon/policies/%s.yaml", policy_name);
    
    // Use simpler command to avoid truncation
    snprintf(cmd, sizeof(cmd), "sudo cp '%s' '%s' && sudo systemctl restart tetragon", src, dst);
    
    int result = system(cmd);
    
    if (result == 0) {
        return create_json_response(200, "{\"success\":true,\"message\":\"Policy deployed and Tetragon restarted\"}");
    } else {
        return create_json_response(500, "{\"error\":\"Failed to deploy policy\"}");
    }
}

// API: DELETE /api/security/policy/:name
struct MHD_Response *api_security_policy_delete(struct MHD_Connection *connection,
                                                const char *method,
                                                const char *policy_name) {
    if (strcmp(method, "DELETE") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path),
             "/home/moh/Documents/cyrenus/config/tetragon/policies/%s.yaml", policy_name);
    
    if (unlink(file_path) == 0) {
        // Also remove from deployed location
        char deployed_path[512];
        snprintf(deployed_path, sizeof(deployed_path), "/etc/tetragon/policies/%s.yaml", policy_name);
        unlink(deployed_path); // Ignore error if not deployed
        
        system("sudo systemctl restart tetragon");
        
        return create_json_response(200, "{\"success\":true,\"message\":\"Policy deleted\"}");
    } else {
        return create_json_response(500, "{\"error\":\"Failed to delete policy\"}");
    }
}

// API: GET /api/security/logs
// Stream Tetragon logs
struct MHD_Response *api_security_logs(struct MHD_Connection *connection,
                                       const char *method,
                                       const char *url) {
    if (strcmp(method, "GET") != 0) {
        return create_response(405, "Method not allowed", "text/plain");
    }
    
    const char *lines_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "lines");
    int lines = lines_str ? atoi(lines_str) : 100;
    
    // Read last N lines from Tetragon log
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tail -n %d /var/log/tetragon/tetragon.log 2>/dev/null", lines);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return create_json_response(500, "{\"error\":\"Failed to read logs\"}");
    }
    
    struct json_object *response = json_object_new_object();
    struct json_object *logs_array = json_object_new_array();
    
    char line[8192];
    while (fgets(line, sizeof(line), fp)) {
        // Try to parse as JSON
        struct json_object *log_obj = json_tokener_parse(line);
        if (log_obj) {
            json_object_array_add(logs_array, log_obj);
        }
    }
    pclose(fp);
    
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
    FILE *fp = fopen("/etc/tetragon/tetragon.yaml", "r");
    if (!fp) {
        return create_json_response(404, "{\"error\":\"Config file not found\"}");
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    fread(content, 1, size, fp);
    content[size] = '\0';
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
    
    // Write to temporary file first
    FILE *fp = fopen("/tmp/tetragon_config_tmp.yaml", "w");
    if (!fp) {
        json_object_put(json);
        return create_json_response(500, "{\"error\":\"Failed to write config\"}");
    }
    
    fprintf(fp, "%s", content);
    fclose(fp);
    
    // Copy to proper location with sudo
    int result = system("sudo cp /tmp/tetragon_config_tmp.yaml /etc/tetragon/tetragon.yaml && sudo systemctl restart tetragon");
    json_object_put(json);
    
    if (result == 0) {
        return create_json_response(200, "{\"success\":true,\"message\":\"Configuration saved and Tetragon restarted\"}");
    } else {
        return create_json_response(500, "{\"error\":\"Failed to save configuration\"}");
    }
}
