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
#include <arpa/inet.h>
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
} tetragon_state = { .inotify_fd = -1, .watch_fd = -1 };

static void safe_copy_json_str(struct json_object *obj, char *dst, size_t dst_size) {
    if (!obj || !dst || dst_size == 0) return;
    const char *s = json_object_get_string(obj);
    if (s) {
        strncpy(dst, s, dst_size - 1);
        dst[dst_size - 1] = '\0';
    }
}

static void extract_process_name_from_path(const char *path, char *out, size_t out_size) {
    if (!path || !path[0] || !out || out_size == 0) return;
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    strncpy(out, base, out_size - 1);
    out[out_size - 1] = '\0';
}

// Initialize Tetragon event monitoring
int tetragon_init(const char *log_file_path) {
    if (!log_file_path) {
        fprintf(stderr, "ERROR: Tetragon log file path is NULL\n");
        return -1;
    }
    
    strncpy(tetragon_state.log_file_path, log_file_path, MAX_FILE_PATH - 1);
    tetragon_state.log_file_path[MAX_FILE_PATH - 1] = '\0';
    
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
    tetragon_state.watch_fd = -1;
    
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
    
    // Timestamp
    struct json_object *time_obj;
    if (json_object_object_get_ex(json_event, "time", &time_obj)) {
        event->timestamp = (uint64_t)time(NULL) * 1000000000ULL;
    } else {
        event->timestamp = (uint64_t)time(NULL) * 1000000000ULL;
    }
    
    // Get process execution info
    struct json_object *process_exec;
    if (json_object_object_get_ex(json_event, "process_exec", &process_exec)) {
        strncpy(event->event_type, EVENT_TYPE_PROCESS_EXEC, sizeof(event->event_type) - 1);
        
        struct json_object *process;
        if (json_object_object_get_ex(process_exec, "process", &process)) {
            struct json_object *tmp;
            
            if (json_object_object_get_ex(process, "pid", &tmp)) {
                event->pid = (uint32_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(process, "uid", &tmp)) {
                event->uid = (uint32_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(process, "binary", &tmp)) {
                safe_copy_json_str(tmp, event->binary_path, MAX_FILE_PATH);
                extract_process_name_from_path(event->binary_path, event->process_name, MAX_PROCESS_NAME);
            }
            if (json_object_object_get_ex(process, "arguments", &tmp)) {
                safe_copy_json_str(tmp, event->command, MAX_COMMAND_LINE);
            }
        }

        // Get parent info
        struct json_object *parent;
        if (json_object_object_get_ex(process_exec, "parent", &parent)) {
            struct json_object *tmp;
            if (json_object_object_get_ex(parent, "pid", &tmp)) {
                event->ppid = (uint32_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(parent, "binary", &tmp)) {
                safe_copy_json_str(tmp, event->parent_binary, MAX_FILE_PATH);
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
            if (func && strstr(func, "file")) {
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
                                safe_copy_json_str(path, event->file_path, MAX_FILE_PATH);
                            }
                        }
                    }
                }
            }
        }
        
        if (json_object_object_get_ex(process_kprobe, "policy_name", &tmp)) {
            safe_copy_json_str(tmp, event->policy_name, MAX_POLICY_NAME);
        }
        
        if (json_object_object_get_ex(process_kprobe, "message", &tmp)) {
            safe_copy_json_str(tmp, event->message, MAX_MESSAGE);
        }
        
        if (json_object_object_get_ex(process_kprobe, "action", &tmp)) {
            safe_copy_json_str(tmp, event->action, sizeof(event->action));
        }
        
        // Get process info
        struct json_object *process;
        if (json_object_object_get_ex(process_kprobe, "process", &process)) {
            if (json_object_object_get_ex(process, "pid", &tmp)) {
                event->pid = (uint32_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(process, "uid", &tmp)) {
                event->uid = (uint32_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(process, "binary", &tmp)) {
                safe_copy_json_str(tmp, event->binary_path, MAX_FILE_PATH);
                extract_process_name_from_path(event->binary_path, event->process_name, MAX_PROCESS_NAME);
            }
            if (json_object_object_get_ex(process, "arguments", &tmp)) {
                safe_copy_json_str(tmp, event->command, MAX_COMMAND_LINE);
            }
        }

        // Get parent info
        struct json_object *parent;
        if (json_object_object_get_ex(process_kprobe, "parent", &parent)) {
            if (json_object_object_get_ex(parent, "pid", &tmp)) {
                event->ppid = (uint32_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(parent, "binary", &tmp)) {
                safe_copy_json_str(tmp, event->parent_binary, MAX_FILE_PATH);
            }
        }

        // Populate human-readable message if Tetragon event omitted it
        if (event->message[0] == '\0') {
            snprintf(event->message, sizeof(event->message), "%s (%s) on %s",
                     event->policy_name[0] ? event->policy_name : "Policy event",
                     event->action[0] ? event->action : "Post",
                     event->process_name[0] ? event->process_name : "process");
        }
    }
    
    // Classify event
    if (strcmp(event->action, "Sigkill") == 0 ||
        strcmp(event->action, "KPROBE_ACTION_SIGKILL") == 0) {
        event->severity = SEVERITY_CRITICAL;
    } else {
        event->severity = tetragon_classify_severity(event->event_type, event->message);
        if (strcmp(event->event_type, EVENT_TYPE_PROCESS_KPROBE) == 0 &&
            event->severity < SEVERITY_WARNING) {
            event->severity = SEVERITY_WARNING;
        }
    }
    event->alert_type = tetragon_classify_alert_type(event->message, event->binary_path);
    
    return 0;
}

// Store event in database
int tetragon_store_event(struct security_event *event) {
    if (!event) return -1;

    char src_ip_str[INET_ADDRSTRLEN] = {0};
    char dst_ip_str[INET_ADDRSTRLEN] = {0};
    const char *src_ptr = NULL;
    const char *dst_ptr = NULL;

    if (event->src_ip != 0 && inet_ntop(AF_INET, &event->src_ip, src_ip_str, sizeof(src_ip_str))) {
        src_ptr = src_ip_str;
    }
    if (event->dst_ip != 0 && inet_ntop(AF_INET, &event->dst_ip, dst_ip_str, sizeof(dst_ip_str))) {
        dst_ptr = dst_ip_str;
    }
    
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
        src_ptr,
        dst_ptr,
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
    
    const char *severity_str = event->severity == SEVERITY_CRITICAL ? "CRITICAL" : "WARNING";
    const char *msg_text = event->message[0]
        ? event->message
        : (event->binary_path[0] ? event->binary_path : "Tetragon security policy triggered");

    struct json_object *alert_obj = json_object_new_object();
    if (!alert_obj) return -1;

    json_object_object_add(alert_obj, "type", json_object_new_string("security_alert"));
    json_object_object_add(alert_obj, "severity", json_object_new_string(severity_str));
    json_object_object_add(alert_obj, "pid", json_object_new_int64((int64_t)event->pid));
    json_object_object_add(alert_obj, "process", json_object_new_string(event->process_name[0] ? event->process_name : "unknown"));
    json_object_object_add(alert_obj, "action", json_object_new_string(event->action));
    json_object_object_add(alert_obj, "policy", json_object_new_string(event->policy_name));
    json_object_object_add(alert_obj, "message", json_object_new_string(msg_text));

    const char *alert_json = json_object_to_json_string(alert_obj);
    if (alert_json) {
        ws_broadcast_message(alert_json);
    }
    json_object_put(alert_obj);
    
    // Update stats
    pthread_mutex_lock(&tetragon_state.stats_mutex);
    tetragon_state.stats.alerts_generated++;
    if (strcmp(event->action, "Sigkill") == 0 ||
        strcmp(event->action, "KPROBE_ACTION_SIGKILL") == 0 ||
        strcmp(event->action, "block") == 0) {
        tetragon_state.stats.events_blocked++;
    }
    pthread_mutex_unlock(&tetragon_state.stats_mutex);
    
    printf("ALERT[%s]: PID: %u, Action: %s, Msg: %s\n", 
           severity_str, event->pid, event->action, msg_text);
    
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
    int waited_logged = 0;
    
    printf("INFO: Tetragon event monitor thread started\n");
    tetragon_state.running = 1;
    
    while (tetragon_state.running) {
        // Wait for or reopen log file (supports delayed Tetragon startup and log rotation)
        if (!log_fp) {
            log_fp = fopen(tetragon_state.log_file_path, "r");
            if (!log_fp) {
                if (!waited_logged) {
                    fprintf(stderr, "INFO: Waiting for Tetragon log file: %s\n", tetragon_state.log_file_path);
                    waited_logged = 1;
                }
                sleep(2);
                continue;
            }
            if (waited_logged) {
                // Reopened or appeared after startup: read from beginning of newly created/rotated file
                waited_logged = 0;
            } else {
                // Initial open on pre-existing log file: tail from end
                fseek(log_fp, 0, SEEK_END);
            }
            if (tetragon_state.watch_fd >= 0) {
                inotify_rm_watch(tetragon_state.inotify_fd, tetragon_state.watch_fd);
            }
            tetragon_state.watch_fd = inotify_add_watch(
                tetragon_state.inotify_fd,
                tetragon_state.log_file_path,
                IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF
            );
        }

        // Check inotify events
        int need_reopen = 0;
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(tetragon_state.inotify_fd, buf, sizeof(buf));
        if (len > 0) {
            ssize_t offset = 0;
            while (offset < len) {
                struct inotify_event *ev = (struct inotify_event *)(buf + offset);
                if (ev->mask & (IN_MOVE_SELF | IN_DELETE_SELF)) {
                    need_reopen = 1;
                }
                offset += (ssize_t)sizeof(struct inotify_event) + ev->len;
            }
        }

        // Drain newly written lines
        while (fgets(line, sizeof(line), log_fp)) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0] != '\0') {
                tetragon_process_json_line(line);
            }
        }
        clearerr(log_fp);

        // Also detect copytruncate rotation cleanly
        struct stat st;
        if (!need_reopen && stat(tetragon_state.log_file_path, &st) == 0) {
            long pos = ftell(log_fp);
            if (pos >= 0 && st.st_size < pos) {
                fseek(log_fp, 0, SEEK_SET);
            }
        }

        if (need_reopen) {
            if (tetragon_state.watch_fd >= 0) {
                inotify_rm_watch(tetragon_state.inotify_fd, tetragon_state.watch_fd);
                tetragon_state.watch_fd = -1;
            }
            fclose(log_fp);
            log_fp = NULL;
            waited_logged = 1; // Read newly rotated file from byte 0
            continue;
        }
        
        usleep(100000); // 100ms
    }
    
    if (log_fp) fclose(log_fp);
    if (tetragon_state.watch_fd >= 0) {
        inotify_rm_watch(tetragon_state.inotify_fd, tetragon_state.watch_fd);
        tetragon_state.watch_fd = -1;
    }
    
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
