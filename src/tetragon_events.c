#include "tetragon_events.h"
#include "database.h"
#include "websocket_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

// Global state
static struct {
    char log_file_path[MAX_FILE_PATH];
    pthread_t monitor_thread;
    int inotify_fd;
    int watch_fd;
    int running;
    struct tetragon_stats stats;
    pthread_mutex_t stats_mutex;
} tetragon_state = {0};

// Initialize Tetragon event monitoring
int tetragon_init(const char *log_file_path) {
    if (!log_file_path) {
        fprintf(stderr, "ERROR: Tetragon log file path is NULL\n");
        return -1;
    }
    
    strncpy(tetragon_state.log_file_path, log_file_path, MAX_FILE_PATH - 1);
    
    // Initialize mutex
    if (pthread_mutex_init(&tetragon_state.stats_mutex, NULL) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize stats mutex\n");
        return -1;
    }
    
    // Initialize inotify
    tetragon_state.inotify_fd = inotify_init1(IN_NONBLOCK);
    if (tetragon_state.inotify_fd < 0) {
        fprintf(stderr, "ERROR: Failed to initialize inotify: %s\n", strerror(errno));
        return -1;
    }
    
    memset(&tetragon_state.stats, 0, sizeof(struct tetragon_stats));
    tetragon_state.running = 0;
    
    printf("INFO: Tetragon event monitor initialized for: %s\n", log_file_path);
    return 0;
}

// Check if Tetragon is running
int tetragon_is_running(void) {
    FILE *fp = popen("systemctl is-active tetragon 2>/dev/null", "r");
    if (!fp) return 0;
    
    char status[16] = {0};
    if (fgets(status, sizeof(status), fp)) {
        // Remove newline
        status[strcspn(status, "\n")] = 0;
        pclose(fp);
        return strcmp(status, "active") == 0;
    }
    
    pclose(fp);
    return 0;
}

// Classify event severity
uint8_t tetragon_classify_severity(const char *function_name, const char *message) {
    if (!message) return SEVERITY_INFO;
    
    // Critical indicators
    if (strstr(message, "CRITICAL") || 
        strstr(message, "RCE detected") ||
        strstr(message, "blocked") ||
        strstr(message, "Sigkill")) {
        return SEVERITY_CRITICAL;
    }
    
    // Error/Warning indicators
    if (strstr(message, "WARNING") ||
        strstr(message, "detected") ||
        strstr(message, "suspicious") ||
        strstr(message, "unauthorized")) {
        return SEVERITY_WARNING;
    }
    
    return SEVERITY_INFO;
}

// Classify alert type
uint32_t tetragon_classify_alert_type(const char *message, const char *binary_path) {
    uint32_t alert_type = 0;
    
    if (!message) return alert_type;
    
    if (strstr(message, "RCE") || strstr(message, "shell spawn")) {
        alert_type |= ALERT_RCE_ATTEMPT;
    }
    if (strstr(message, "privilege") || strstr(message, "setuid")) {
        alert_type |= ALERT_PRIVILEGE_ESCALATION;
    }
    if (strstr(message, "reverse shell")) {
        alert_type |= ALERT_REVERSE_SHELL;
    }
    if (strstr(message, "webshell") || strstr(message, "web directory")) {
        alert_type |= ALERT_WEBSHELL_UPLOAD;
    }
    if (strstr(message, "file") || strstr(message, "integrity")) {
        alert_type |= ALERT_FILE_INTEGRITY;
    }
    if (strstr(message, "inject") || strstr(message, "ptrace")) {
        alert_type |= ALERT_PROCESS_INJECTION;
    }
    if (strstr(message, "cron") || strstr(message, "systemd") || strstr(message, "persistence")) {
        alert_type |= ALERT_PERSISTENCE;
    }
    if (strstr(message, "namespace") || strstr(message, "container")) {
        alert_type |= ALERT_CONTAINER_ESCAPE;
    }
    
    return alert_type;
}

// Parse Tetragon JSON event
int tetragon_parse_event(struct json_object *json_event, struct security_event *event) {
    if (!json_event || !event) return -1;
    
    memset(event, 0, sizeof(struct security_event));
    
    // Get timestamp
    struct json_object *time_obj;
    if (json_object_object_get_ex(json_event, "time", &time_obj)) {
        // Parse ISO8601 timestamp - simplified version
        event->timestamp = time(NULL) * 1000000000ULL; // Use current time as fallback
    }
    
    // Get process execution info
    struct json_object *process_exec;
    if (json_object_object_get_ex(json_event, "process_exec", &process_exec)) {
        strncpy(event->event_type, EVENT_TYPE_PROCESS_EXEC, sizeof(event->event_type) - 1);
        
        struct json_object *process;
        if (json_object_object_get_ex(process_exec, "process", &process)) {
            struct json_object *tmp;
            
            if (json_object_object_get_ex(process, "pid", &tmp)) {
                event->pid = json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(process, "binary", &tmp)) {
                strncpy(event->binary_path, json_object_get_string(tmp), MAX_FILE_PATH - 1);
            }
            if (json_object_object_get_ex(process, "arguments", &tmp)) {
                const char *args = json_object_get_string(tmp);
                strncpy(event->command, args, MAX_COMMAND_LINE - 1);
            }
            
            // Get parent info
            struct json_object *parent;
            if (json_object_object_get_ex(process_exec, "parent", &parent)) {
                if (json_object_object_get_ex(parent, "pid", &tmp)) {
                    event->ppid = json_object_get_int(tmp);
                }
                if (json_object_object_get_ex(parent, "binary", &tmp)) {
                    strncpy(event->parent_binary, json_object_get_string(tmp), MAX_FILE_PATH - 1);
                }
            }
        }
    }
    
    // Get kprobe info
    struct json_object *process_kprobe;
    if (json_object_object_get_ex(json_event, "process_kprobe", &process_kprobe)) {
        strncpy(event->event_type, EVENT_TYPE_PROCESS_KPROBE, sizeof(event->event_type) - 1);
        
        struct json_object *tmp;
        if (json_object_object_get_ex(process_kprobe, "function_name", &tmp)) {
            const char *func = json_object_get_string(tmp);
            
            // Extract info based on function
            if (strstr(func, "file")) {
                struct json_object *args;
                if (json_object_object_get_ex(process_kprobe, "args", &args) && 
                    json_object_is_type(args, json_type_array)) {
                    int len = json_object_array_length(args);
                    for (int i = 0; i < len; i++) {
                        struct json_object *arg = json_object_array_get_idx(args, i);
                        struct json_object *file_arg;
                        if (json_object_object_get_ex(arg, "file_arg", &file_arg)) {
                            struct json_object *path;
                            if (json_object_object_get_ex(file_arg, "path", &path)) {
                                strncpy(event->file_path, json_object_get_string(path), MAX_FILE_PATH - 1);
                            }
                        }
                    }
                }
            }
        }
        
        if (json_object_object_get_ex(process_kprobe, "policy_name", &tmp)) {
            strncpy(event->policy_name, json_object_get_string(tmp), MAX_POLICY_NAME - 1);
        }
        
        if (json_object_object_get_ex(process_kprobe, "message", &tmp)) {
            strncpy(event->message, json_object_get_string(tmp), MAX_MESSAGE - 1);
        }
        
        if (json_object_object_get_ex(process_kprobe, "action", &tmp)) {
            strncpy(event->action, json_object_get_string(tmp), sizeof(event->action) - 1);
        }
        
        // Get process info
        struct json_object *process;
        if (json_object_object_get_ex(process_kprobe, "process", &process)) {
            if (json_object_object_get_ex(process, "pid", &tmp)) {
                event->pid = json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(process, "binary", &tmp)) {
                strncpy(event->binary_path, json_object_get_string(tmp), MAX_FILE_PATH - 1);
            }
        }
    }
    
    // Classify event
    event->severity = tetragon_classify_severity(event->event_type, event->message);
    event->alert_type = tetragon_classify_alert_type(event->message, event->binary_path);
    
    return 0;
}

// Store event in database
int tetragon_store_event(struct security_event *event) {
    if (!event) return -1;
    
    return db_insert_security_event(
        event->timestamp,
        event->event_type,
        event->severity,
        event->process_name[0] ? event->process_name : "unknown",
        event->pid,
        event->ppid,
        event->uid,
        event->command,
        event->binary_path,
        event->parent_binary,
        event->action,
        event->policy_name,
        event->src_ip ? inet_ntoa(*(struct in_addr*)&event->src_ip) : NULL,
        event->dst_ip ? inet_ntoa(*(struct in_addr*)&event->dst_ip) : NULL,
        event->dst_port,
        event->file_path[0] ? event->file_path : NULL,
        event->file_operation[0] ? event->file_operation : NULL,
        event->metadata_json
    );
}

// Generate alert
int tetragon_generate_alert(struct security_event *event) {
    if (!event || event->severity < SEVERITY_WARNING) {
        return 0; // Only alert on warnings and above
    }
    
    // Create alert JSON - use smaller fields to avoid truncation
    char alert_json[1024];
    const char *severity_str = event->severity == SEVERITY_CRITICAL ? "CRITICAL" : "WARNING";
    
    snprintf(alert_json, sizeof(alert_json),
        "{"
        "\"type\":\"security_alert\","
        "\"severity\":\"%s\","
        "\"pid\":%u,"
        "\"action\":\"%s\""
        "}",
        severity_str,
        event->pid,
        event->action
    );
    
    // Send via WebSocket
    ws_broadcast_message(alert_json);
    
    // Update stats
    pthread_mutex_lock(&tetragon_state.stats_mutex);
    tetragon_state.stats.alerts_generated++;
    if (strcmp(event->action, "Sigkill") == 0 || strcmp(event->action, "block") == 0) {
        tetragon_state.stats.events_blocked++;
    }
    pthread_mutex_unlock(&tetragon_state.stats_mutex);
    
    printf("ALERT[%s]: PID: %u, Action: %s\n", 
           severity_str, event->pid, event->action);
    
    return 0;
}

// Process a single JSON line
int tetragon_process_json_line(const char *json_line) {
    if (!json_line || strlen(json_line) == 0) return -1;
    
    struct json_object *json_event = json_tokener_parse(json_line);
    if (!json_event) {
        fprintf(stderr, "ERROR: Failed to parse JSON: %s\n", json_line);
        return -1;
    }
    
    struct security_event event;
    if (tetragon_parse_event(json_event, &event) == 0) {
        // Store in database
        tetragon_store_event(&event);
        
        // Generate alert if needed
        if (event.severity >= SEVERITY_WARNING) {
            tetragon_generate_alert(&event);
        } else {
             // For INFO/low severity events, just send a silent update trigger
             // to refresh the list without a toast notification
             ws_broadcast_message("{\"type\":\"security_update\"}");
        }
        
        // Update stats
        pthread_mutex_lock(&tetragon_state.stats_mutex);
        tetragon_state.stats.total_events++;
        if (strcmp(event.event_type, EVENT_TYPE_PROCESS_EXEC) == 0) {
            tetragon_state.stats.process_exec_events++;
        }
        pthread_mutex_unlock(&tetragon_state.stats_mutex);
    }
    
    json_object_put(json_event);
    return 0;
}

// Event monitor thread
void *tetragon_event_monitor_thread(void *arg) {
    (void)arg;
    
    FILE *log_fp = NULL;
    char line[8192];
    
    printf("INFO: Tetragon event monitor thread started\n");
    
    // Open log file
    log_fp = fopen(tetragon_state.log_file_path, "r");
    if (!log_fp) {
        fprintf(stderr, "ERROR: Failed to open Tetragon log: %s\n", tetragon_state.log_file_path);
        return NULL;
    }
    
    // Seek to end (we only want new events)
    fseek(log_fp, 0, SEEK_END);
    
    // Add inotify watch
    tetragon_state.watch_fd = inotify_add_watch(tetragon_state.inotify_fd, 
                                                 tetragon_state.log_file_path, 
                                                 IN_MODIFY);
    if (tetragon_state.watch_fd < 0) {
        fprintf(stderr, "ERROR: Failed to add inotify watch: %s\n", strerror(errno));
        fclose(log_fp);
        return NULL;
    }
    
    tetragon_state.running = 1;
    
    while (tetragon_state.running) {
        // Check for new data
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(tetragon_state.inotify_fd, buf, sizeof(buf));
        
        if (len > 0) {
            // File was modified, read new lines
            while (fgets(line, sizeof(line), log_fp)) {
                // Remove newline
                line[strcspn(line, "\n")] = 0;
                tetragon_process_json_line(line);
            }
            // Clear EOF so we can read again when more data arrives
            clearerr(log_fp);
        }
        
        // Sleep briefly to avoid busy loop
        usleep(100000); // 100ms
    }
    
    if (log_fp) fclose(log_fp);
    inotify_rm_watch(tetragon_state.inotify_fd, tetragon_state.watch_fd);
    
    printf("INFO: Tetragon event monitor thread stopped\n");
    return NULL;
}

// Start monitor
int tetragon_start_monitor(void) {
    if (tetragon_state.running) {
        fprintf(stderr, "WARNING: Tetragon monitor already running\n");
        return -1;
    }
    
    // Check if Tetragon is running
    if (!tetragon_is_running()) {
        fprintf(stderr, "WARNING: Tetragon service is not running\n");
        // Continue anyway - it might start later
    }
    
    if (pthread_create(&tetragon_state.monitor_thread, NULL, 
                       tetragon_event_monitor_thread, NULL) != 0) {
        fprintf(stderr, "ERROR: Failed to create monitor thread\n");
        return -1;
    }
    
    printf("INFO: Tetragon event monitor started\n");
    return 0;
}

// Stop monitor
void tetragon_stop_monitor(void) {
    if (!tetragon_state.running) return;
    
    tetragon_state.running = 0;
    pthread_join(tetragon_state.monitor_thread, NULL);
    printf("INFO: Tetragon monitor stopped\n");
}

// Get stats
int tetragon_get_stats(struct tetragon_stats *stats) {
    if (!stats) return -1;
    
    pthread_mutex_lock(&tetragon_state.stats_mutex);
    memcpy(stats, &tetragon_state.stats, sizeof(struct tetragon_stats));
    stats->last_update_time = time(NULL);
    pthread_mutex_unlock(&tetragon_state.stats_mutex);
    
    return 0;
}

// Cleanup
void tetragon_cleanup(void) {
    tetragon_stop_monitor();
    
    if (tetragon_state.inotify_fd >= 0) {
        close(tetragon_state.inotify_fd);
    }
    
    pthread_mutex_destroy(&tetragon_state.stats_mutex);
    printf("INFO: Tetragon event monitor cleaned up\n");
}
