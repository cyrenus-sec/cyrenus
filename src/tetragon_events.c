#define _DEFAULT_SOURCE
#include "tetragon_events.h"
#include "api_handlers.h"
#include "database.h"
#include "websocket_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

extern struct database *g_db;

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

static pthread_mutex_t g_ws_coalesce_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_sec_ws_update_ms = 0;
static int g_pending_sec_ws_update = 0;

static pthread_mutex_t g_tg_running_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_tg_running_checked_ms = 0;
static int g_tg_running_cached = 0;
static pid_t g_tg_cached_pid = 0;

static uint64_t monotonic_ms_now(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void flush_pending_security_ws_update(int force) {
    uint64_t now_ms = monotonic_ms_now();
    int should_send = 0;

    pthread_mutex_lock(&g_ws_coalesce_mutex);
    if (g_pending_sec_ws_update &&
        (force || g_last_sec_ws_update_ms == 0 || (now_ms - g_last_sec_ws_update_ms) >= 2000ULL)) {
        g_pending_sec_ws_update = 0;
        g_last_sec_ws_update_ms = now_ms;
        should_send = 1;
    }
    pthread_mutex_unlock(&g_ws_coalesce_mutex);

    if (should_send) {
        api_security_invalidate_stats_cache();
        ws_broadcast_message("{\"type\":\"security_update\"}");
    }
}

static void queue_security_ws_update(void) {
    pthread_mutex_lock(&g_ws_coalesce_mutex);
    g_pending_sec_ws_update = 1;
    pthread_mutex_unlock(&g_ws_coalesce_mutex);
    flush_pending_security_ws_update(0);
}

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

static int ci_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle || !needle[0]) return 0;
    size_t nlen = strlen(needle);
    for (const char *h = haystack; *h != '\0'; h++) {
        size_t i = 0;
        while (i < nlen && h[i] != '\0' &&
               tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static int mem_contains(const char *buf, size_t len, const char *needle) {
    if (!buf || !needle || !needle[0] || len == 0) return 0;
    size_t nlen = strlen(needle);
    if (nlen > len) return 0;
    for (size_t i = 0; i <= len - nlen; i++) {
        if (memcmp(buf + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

static void normalize_tetragon_ip(const char *raw, char *out, size_t out_len) {
    if (!raw || !raw[0] || !out || out_len == 0) return;
    const char *src = raw;
    if (strncasecmp(raw, "::ffff:", 7) == 0) {
        src = raw + 7;
    }
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, src, &v4) == 1) {
        if (inet_ntop(AF_INET, &v4, out, (socklen_t)out_len)) return;
    }
    if (inet_pton(AF_INET6, raw, &v6) == 1) {
        if (inet_ntop(AF_INET6, &v6, out, (socklen_t)out_len)) return;
    }
    snprintf(out, out_len, "%s", raw);
}

static uint64_t parse_iso8601_ns(struct json_object *time_obj) {
    uint64_t fallback = (uint64_t)time(NULL) * 1000000000ULL;
    if (!time_obj) return fallback;

    if (json_object_is_type(time_obj, json_type_int)) {
        int64_t v = json_object_get_int64(time_obj);
        if (v <= 0) return fallback;
        if (v < 3000000000LL) return (uint64_t)v * 1000000000ULL;
        if (v < 3000000000000LL) return (uint64_t)v * 1000000ULL;
        return (uint64_t)v;
    }

    const char *s = json_object_get_string(time_obj);
    if (!s || !s[0]) return fallback;

    int yr = 0, mon = 0, day = 0, hr = 0, min = 0, sec = 0;
    int consumed = 0;
    if (sscanf(s, "%4d-%2d-%2d%*1[Tt ]%2d:%2d:%2d%n",
               &yr, &mon, &day, &hr, &min, &sec, &consumed) < 6 || consumed < 19) {
        return fallback;
    }

    struct tm tmv = {0};
    tmv.tm_year = yr - 1900;
    tmv.tm_mon = mon - 1;
    tmv.tm_mday = day;
    tmv.tm_hour = hr;
    tmv.tm_min = min;
    tmv.tm_sec = sec;
    tmv.tm_isdst = 0;

    time_t epoch = timegm(&tmv);
    if (epoch == (time_t)-1) return fallback;

    const char *p = s + consumed;
    uint64_t subsec_ns = 0;
    if (*p == '.' || *p == ',') {
        p++;
        uint64_t mult = 100000000ULL;
        while (isdigit((unsigned char)*p)) {
            if (mult > 0) {
                subsec_ns += (uint64_t)(*p - '0') * mult;
                mult /= 10;
            }
            p++;
        }
    }

    int tz_offset_sec = 0;
    if (*p == '+' || *p == '-') {
        int sign = (*p == '+') ? 1 : -1;
        p++;
        int tzh = 0, tzm = 0;
        if (sscanf(p, "%2d:%2d", &tzh, &tzm) == 2 ||
            sscanf(p, "%2d%2d", &tzh, &tzm) >= 1) {
            tz_offset_sec = sign * (tzh * 3600 + tzm * 60);
        }
    }

    int64_t adj_epoch = (int64_t)epoch - tz_offset_sec;
    if (adj_epoch < 0) return fallback;
    return (uint64_t)adj_epoch * 1000000000ULL + subsec_ns;
}

static int is_web_server_bin(const char *path) {
    return ci_contains(path, "nginx") || ci_contains(path, "apache") ||
           ci_contains(path, "httpd") || ci_contains(path, "php-fpm") ||
           ci_contains(path, "caddy") || ci_contains(path, "uvicorn") ||
           ci_contains(path, "gunicorn") || ci_contains(path, "node");
}

static int is_shell_bin(const char *path) {
    if (!path || !path[0]) return 0;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strcmp(base, "sh") == 0 || strcmp(base, "bash") == 0 ||
           strcmp(base, "dash") == 0 || strcmp(base, "ash") == 0 ||
           strcmp(base, "zsh") == 0 || strcmp(base, "ksh") == 0;
}

static int is_attack_tool_bin(const char *path) {
    return ci_contains(path, "sqlmap") || ci_contains(path, "nikto") ||
           ci_contains(path, "nmap") || ci_contains(path, "hydra") ||
           ci_contains(path, "masscan") || ci_contains(path, "ncat") ||
           ci_contains(path, "socat") || ci_contains(path, "metasploit") ||
           ci_contains(path, "msfconsole");
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

static int pid_is_tetragon(const char *pid_str) {
    if (!pid_str || !pid_str[0]) return 0;

    char path[300];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid_str);
    FILE *fp = fopen(path, "r");
    if (fp) {
        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), fp)) {
            comm[strcspn(comm, "\r\n")] = '\0';
            if (strcmp(comm, "tetragon") == 0 || strncmp(comm, "tetragon-", 9) == 0) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    fp = fopen(path, "rb");
    if (fp) {
        char cmd[256] = {0};
        size_t n = fread(cmd, 1, sizeof(cmd) - 1, fp);
        fclose(fp);
        if (n > 0 && mem_contains(cmd, n, "tetragon")) {
            return 1;
        }
    }
    return 0;
}

// Check if Tetragon is running without shelling out to systemctl
int tetragon_is_running(void) {
    uint64_t now_ms = monotonic_ms_now();

    pthread_mutex_lock(&g_tg_running_mutex);

    if (g_tg_running_checked_ms != 0 &&
        now_ms >= g_tg_running_checked_ms &&
        (now_ms - g_tg_running_checked_ms) < 5000ULL) {
        if (g_tg_running_cached == 0) {
            pthread_mutex_unlock(&g_tg_running_mutex);
            return 0;
        }
        if (g_tg_cached_pid > 1 &&
            (kill(g_tg_cached_pid, 0) == 0 || errno == EPERM)) {
            pthread_mutex_unlock(&g_tg_running_mutex);
            return 1;
        }
    }

    // 1. Fast path: check PID file first and verify process identity in /proc/<pid>
    FILE *pidfp = fopen("/var/run/tetragon/tetragon.pid", "r");
    if (pidfp) {
        long pid = 0;
        int parsed = (fscanf(pidfp, "%ld", &pid) == 1);
        fclose(pidfp);
        if (parsed && pid > 1 && (kill((pid_t)pid, 0) == 0 || errno == EPERM)) {
            char pid_buf[32];
            snprintf(pid_buf, sizeof(pid_buf), "%ld", pid);
            if (pid_is_tetragon(pid_buf)) {
                g_tg_running_cached = 1;
                g_tg_cached_pid = (pid_t)pid;
                g_tg_running_checked_ms = monotonic_ms_now();
                pthread_mutex_unlock(&g_tg_running_mutex);
                return 1;
            }
        }
    }

    // 2. Fallback: scan /proc if PID file is missing or stale
    int found = 0;
    pid_t found_pid = 0;
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (!isdigit((unsigned char)ent->d_name[0])) continue;
            int numeric = 1;
            for (const char *p = ent->d_name; *p; p++) {
                if (!isdigit((unsigned char)*p)) { numeric = 0; break; }
            }
            if (!numeric) continue;

            if (pid_is_tetragon(ent->d_name)) {
                found = 1;
                found_pid = (pid_t)strtol(ent->d_name, NULL, 10);
                break;
            }
        }
        closedir(dir);
    }

    g_tg_running_cached = found;
    g_tg_cached_pid = found_pid;
    g_tg_running_checked_ms = monotonic_ms_now();
    pthread_mutex_unlock(&g_tg_running_mutex);
    return found;
}

// Classify event severity
uint8_t tetragon_classify_severity(const char *function_name, const char *message) {
    const char *msg = message ? message : "";
    const char *fn = function_name ? function_name : "";

    if (ci_contains(msg, "CRITICAL") ||
        ci_contains(msg, "RCE") ||
        ci_contains(msg, "reverse shell") ||
        ci_contains(msg, "webshell") ||
        ci_contains(msg, "blocked") ||
        ci_contains(msg, "Sigkill") ||
        ci_contains(msg, "privilege escalation") ||
        ci_contains(msg, "escape")) {
        return SEVERITY_CRITICAL;
    }

    if (ci_contains(msg, "ERROR") ||
        ci_contains(msg, "unauthorized") ||
        ci_contains(msg, "injection") ||
        ci_contains(msg, "persistence") ||
        ci_contains(msg, "integrity") ||
        ci_contains(msg, "attack tool") ||
        ci_contains(fn, "ptrace") ||
        ci_contains(fn, "commit_creds")) {
        return SEVERITY_ERROR;
    }

    if (ci_contains(msg, "WARNING") ||
        ci_contains(msg, "detected") ||
        ci_contains(msg, "suspicious") ||
        ci_contains(msg, "outbound")) {
        return SEVERITY_WARNING;
    }

    return SEVERITY_INFO;
}

// Classify alert type
uint32_t tetragon_classify_alert_type(const char *message, const char *binary_path) {
    uint32_t alert_type = 0;
    const char *msg = message ? message : "";
    const char *bin = binary_path ? binary_path : "";

    if (ci_contains(msg, "RCE") || ci_contains(msg, "shell spawn") ||
        ci_contains(msg, "command injection")) {
        alert_type |= ALERT_RCE_ATTEMPT;
    }
    if (ci_contains(msg, "privilege") || ci_contains(msg, "setuid") ||
        ci_contains(msg, "capability") || ci_contains(bin, "/sudo")) {
        alert_type |= ALERT_PRIVILEGE_ESCALATION;
    }
    if (ci_contains(msg, "reverse shell") || ci_contains(msg, "outbound") ||
        ci_contains(bin, "/ncat") || ci_contains(bin, "/socat")) {
        alert_type |= ALERT_REVERSE_SHELL;
    }
    if (ci_contains(msg, "webshell") || ci_contains(msg, "web directory") ||
        ci_contains(msg, "/var/www")) {
        alert_type |= ALERT_WEBSHELL_UPLOAD;
    }
    if (ci_contains(msg, "file") || ci_contains(msg, "integrity") ||
        ci_contains(msg, "/etc/passwd") || ci_contains(msg, "/etc/shadow") ||
        ci_contains(msg, "/etc/sudoers")) {
        alert_type |= ALERT_FILE_INTEGRITY;
    }
    if (ci_contains(msg, "inject") || ci_contains(msg, "ptrace") ||
        ci_contains(msg, "memfd")) {
        alert_type |= ALERT_PROCESS_INJECTION;
    }
    if (ci_contains(msg, "cron") || ci_contains(msg, "systemd") ||
        ci_contains(msg, "persistence") || ci_contains(msg, "authorized_keys")) {
        alert_type |= ALERT_PERSISTENCE;
    }
    if (ci_contains(msg, "namespace") || ci_contains(msg, "container") ||
        ci_contains(msg, "escape")) {
        alert_type |= ALERT_CONTAINER_ESCAPE;
    }

    return alert_type;
}

static void parse_process_fields(struct json_object *proc_obj,
                                 uint32_t *pid_out, uint32_t *uid_out,
                                 char *bin_out, size_t bin_len,
                                 char *name_out, size_t name_len,
                                 char *cmd_out, size_t cmd_len) {
    if (!proc_obj) return;
    struct json_object *tmp;
    if (pid_out && json_object_object_get_ex(proc_obj, "pid", &tmp)) {
        *pid_out = (uint32_t)json_object_get_int(tmp);
    }
    if (uid_out && json_object_object_get_ex(proc_obj, "uid", &tmp)) {
        *uid_out = (uint32_t)json_object_get_int(tmp);
    }
    if (bin_out && json_object_object_get_ex(proc_obj, "binary", &tmp)) {
        safe_copy_json_str(tmp, bin_out, bin_len);
        if (name_out && name_len > 0) {
            extract_process_name_from_path(bin_out, name_out, name_len);
        }
    }
    if (cmd_out && json_object_object_get_ex(proc_obj, "arguments", &tmp)) {
        safe_copy_json_str(tmp, cmd_out, cmd_len);
    }
}

static void parse_parent_fields(struct json_object *container,
                                uint32_t *ppid_out, char *pbin_out, size_t pbin_len) {
    if (!container) return;
    struct json_object *parent = NULL;
    if (!json_object_object_get_ex(container, "parent", &parent)) {
        json_object_object_get_ex(container, "parent_process", &parent);
    }
    if (!parent) return;
    struct json_object *tmp;
    if (ppid_out && json_object_object_get_ex(parent, "pid", &tmp)) {
        *ppid_out = (uint32_t)json_object_get_int(tmp);
    }
    if (pbin_out && json_object_object_get_ex(parent, "binary", &tmp)) {
        safe_copy_json_str(tmp, pbin_out, pbin_len);
    }
}

static void parse_kprobe_args(struct json_object *args, const char *func_name, struct security_event *event) {
    if (!args || !json_object_is_type(args, json_type_array)) return;
    int len = json_object_array_length(args);
    for (int i = 0; i < len; i++) {
        struct json_object *arg = json_object_array_get_idx(args, i);
        if (!arg) continue;

        struct json_object *file_arg = NULL;
        if (json_object_object_get_ex(arg, "file_arg", &file_arg)) {
            struct json_object *path_obj = NULL;
            if (json_object_object_get_ex(file_arg, "path", &path_obj)) {
                safe_copy_json_str(path_obj, event->file_path, MAX_FILE_PATH);
                if (event->file_operation[0] == '\0' && func_name) {
                    if (ci_contains(func_name, "write")) snprintf(event->file_operation, sizeof(event->file_operation), "write");
                    else if (ci_contains(func_name, "unlink") || ci_contains(func_name, "rmdir")) snprintf(event->file_operation, sizeof(event->file_operation), "delete");
                    else if (ci_contains(func_name, "chmod") || ci_contains(func_name, "chown")) snprintf(event->file_operation, sizeof(event->file_operation), "chmod");
                    else if (ci_contains(func_name, "read")) snprintf(event->file_operation, sizeof(event->file_operation), "read");
                    else snprintf(event->file_operation, sizeof(event->file_operation), "open");
                }
            }
        }

        struct json_object *sock_arg = NULL;
        if (json_object_object_get_ex(arg, "sock_arg", &sock_arg)) {
            struct json_object *tmp = NULL;
            if (json_object_object_get_ex(sock_arg, "saddr", &tmp)) {
                const char *s = json_object_get_string(tmp);
                if (s && s[0]) normalize_tetragon_ip(s, event->src_ip, sizeof(event->src_ip));
            }
            if (json_object_object_get_ex(sock_arg, "daddr", &tmp)) {
                const char *d = json_object_get_string(tmp);
                if (d && d[0]) normalize_tetragon_ip(d, event->dst_ip, sizeof(event->dst_ip));
            }
            if (json_object_object_get_ex(sock_arg, "sport", &tmp)) {
                event->src_port = (uint16_t)json_object_get_int(tmp);
            }
            if (json_object_object_get_ex(sock_arg, "dport", &tmp)) {
                event->dst_port = (uint16_t)json_object_get_int(tmp);
            }
        }

        struct json_object *str_arg = NULL;
        if (event->file_path[0] == '\0' && json_object_object_get_ex(arg, "string_arg", &str_arg) && func_name &&
            (ci_contains(func_name, "file") || ci_contains(func_name, "open") ||
             ci_contains(func_name, "unlink") || ci_contains(func_name, "exec"))) {
            safe_copy_json_str(str_arg, event->file_path, MAX_FILE_PATH);
        }
    }
}

// Parse Tetragon JSON event
int tetragon_parse_event(struct json_object *json_event, struct security_event *event) {
    if (!json_event || !event) return -1;

    memset(event, 0, sizeof(struct security_event));

    struct json_object *time_obj = NULL;
    if (json_object_object_get_ex(json_event, "time", &time_obj)) {
        event->timestamp = parse_iso8601_ns(time_obj);
    } else {
        event->timestamp = (uint64_t)time(NULL) * 1000000000ULL;
    }

    char func_name[256] = {0};

    // Process execution event
    struct json_object *process_exec = NULL;
    if (json_object_object_get_ex(json_event, "process_exec", &process_exec)) {
        snprintf(event->event_type, sizeof(event->event_type), "%s", EVENT_TYPE_PROCESS_EXEC);

        struct json_object *process = NULL;
        if (json_object_object_get_ex(process_exec, "process", &process)) {
            parse_process_fields(process, &event->pid, &event->uid,
                                 event->binary_path, MAX_FILE_PATH,
                                 event->process_name, MAX_PROCESS_NAME,
                                 event->command, MAX_COMMAND_LINE);
        }
        parse_parent_fields(process_exec, &event->ppid, event->parent_binary, MAX_FILE_PATH);

        if (is_web_server_bin(event->parent_binary) && is_shell_bin(event->binary_path)) {
            snprintf(event->message, sizeof(event->message),
                     "CRITICAL RCE detected: %.256s spawned shell %.256s",
                     event->parent_binary, event->binary_path);
            snprintf(event->policy_name, sizeof(event->policy_name), "process-monitoring");
            event->alert_type |= ALERT_RCE_ATTEMPT;
        } else if (is_attack_tool_bin(event->binary_path) || is_attack_tool_bin(event->command)) {
            snprintf(event->message, sizeof(event->message),
                     "WARNING: Suspicious attack tool executed: %.512s",
                     event->binary_path[0] ? event->binary_path : event->process_name);
            snprintf(event->policy_name, sizeof(event->policy_name), "process-monitoring");
        }
    }

    // Kprobe event
    struct json_object *process_kprobe = NULL;
    if (json_object_object_get_ex(json_event, "process_kprobe", &process_kprobe)) {
        snprintf(event->event_type, sizeof(event->event_type), "%s", EVENT_TYPE_PROCESS_KPROBE);

        struct json_object *tmp = NULL;
        if (json_object_object_get_ex(process_kprobe, "function_name", &tmp)) {
            safe_copy_json_str(tmp, func_name, sizeof(func_name));
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

        struct json_object *process = NULL;
        if (json_object_object_get_ex(process_kprobe, "process", &process)) {
            parse_process_fields(process, &event->pid, &event->uid,
                                 event->binary_path, MAX_FILE_PATH,
                                 event->process_name, MAX_PROCESS_NAME,
                                 event->command, MAX_COMMAND_LINE);
        }
        parse_parent_fields(process_kprobe, &event->ppid, event->parent_binary, MAX_FILE_PATH);

        struct json_object *args = NULL;
        if (json_object_object_get_ex(process_kprobe, "args", &args)) {
            parse_kprobe_args(args, func_name, event);
        }

        if (event->message[0] == '\0') {
            snprintf(event->message, sizeof(event->message), "%s (%s) on %s",
                     event->policy_name[0] ? event->policy_name : "Policy event",
                     event->action[0] ? event->action : "Post",
                     event->process_name[0] ? event->process_name : "process");
        }
    }

    // Tracepoint event
    struct json_object *process_tp = NULL;
    if (event->event_type[0] == '\0' && json_object_object_get_ex(json_event, "process_tracepoint", &process_tp)) {
        snprintf(event->event_type, sizeof(event->event_type), "%s", EVENT_TYPE_PROCESS_TRACEPOINT);
        struct json_object *tmp = NULL;
        if (json_object_object_get_ex(process_tp, "policy_name", &tmp)) {
            safe_copy_json_str(tmp, event->policy_name, MAX_POLICY_NAME);
        }
        if (json_object_object_get_ex(process_tp, "message", &tmp)) {
            safe_copy_json_str(tmp, event->message, MAX_MESSAGE);
        }
        struct json_object *process = NULL;
        if (json_object_object_get_ex(process_tp, "process", &process)) {
            parse_process_fields(process, &event->pid, &event->uid,
                                 event->binary_path, MAX_FILE_PATH,
                                 event->process_name, MAX_PROCESS_NAME,
                                 event->command, MAX_COMMAND_LINE);
        }
        parse_parent_fields(process_tp, &event->ppid, event->parent_binary, MAX_FILE_PATH);
    }

    // Process exit event (parsed for stats accounting; not persisted as alert spam)
    struct json_object *process_exit = NULL;
    if (event->event_type[0] == '\0' && json_object_object_get_ex(json_event, "process_exit", &process_exit)) {
        snprintf(event->event_type, sizeof(event->event_type), "%s", EVENT_TYPE_PROCESS_EXIT);
        struct json_object *process = NULL;
        if (json_object_object_get_ex(process_exit, "process", &process)) {
            parse_process_fields(process, &event->pid, &event->uid,
                                 event->binary_path, MAX_FILE_PATH,
                                 event->process_name, MAX_PROCESS_NAME,
                                 event->command, MAX_COMMAND_LINE);
        }
        parse_parent_fields(process_exit, &event->ppid, event->parent_binary, MAX_FILE_PATH);
        event->severity = SEVERITY_INFO;
        return 0;
    }

    if (event->event_type[0] == '\0') {
        return -1;
    }

    if (event->command[0] == '\0' && event->binary_path[0] != '\0') {
        snprintf(event->command, sizeof(event->command), "%.2040s", event->binary_path);
    }

    // Classify alert type across message + paths
    char combined_ctx[2048];
    snprintf(combined_ctx, sizeof(combined_ctx), "%.512s %.128s %.512s %.512s",
             event->message, event->policy_name, event->file_path, event->parent_binary);
    event->alert_type |= tetragon_classify_alert_type(combined_ctx, event->binary_path);

    // Classify severity
    if (strcmp(event->action, "Sigkill") == 0 ||
        strcmp(event->action, "KPROBE_ACTION_SIGKILL") == 0) {
        event->severity = SEVERITY_CRITICAL;
    } else {
        uint8_t s1 = tetragon_classify_severity(func_name, event->message);
        uint8_t s2 = tetragon_classify_severity(func_name, event->policy_name);
        event->severity = (s1 > s2) ? s1 : s2;
        if (strcmp(event->event_type, EVENT_TYPE_PROCESS_KPROBE) == 0 &&
            event->severity < SEVERITY_WARNING) {
            event->severity = SEVERITY_WARNING;
        }
    }

    return 0;
}

// Store event in database and optionally return inserted row ID
int tetragon_store_event_ex(struct security_event *event, int64_t *new_id_out) {
    if (!event) return -1;

    return db_insert_security_event_ex(
        (int64_t)event->timestamp,
        event->event_type,
        event->severity,
        event->process_name[0] ? event->process_name : "unknown",
        (int)event->pid,
        (int)event->ppid,
        (int)event->uid,
        event->command,
        event->binary_path,
        event->parent_binary,
        event->action,
        event->policy_name,
        event->src_ip[0] ? event->src_ip : NULL,
        event->dst_ip[0] ? event->dst_ip : NULL,
        (int)event->dst_port,
        event->file_path[0] ? event->file_path : NULL,
        event->file_operation[0] ? event->file_operation : NULL,
        event->metadata_json,
        new_id_out
    );
}

int tetragon_store_event(struct security_event *event) {
    return tetragon_store_event_ex(event, NULL);
}

int tetragon_correlate_events(const char *src_ip, uint32_t pid, const char *attack_type,
                              int64_t network_event_id, int64_t security_event_id,
                              const char *description, const char *details) {
    if (!g_db || !g_db->is_open) return -1;

    char ip_buf[46];
    snprintf(ip_buf, sizeof(ip_buf), "%s", (src_ip && src_ip[0]) ? src_ip : "local");
    const char *atk_label = (attack_type && attack_type[0]) ? attack_type : "CORRELATED_INTRUSION";

    time_t now = time(NULL);
    if (database_has_recent_correlation(g_db, ip_buf, atk_label, now - 60)) {
        return 0; // Deduplicate identical correlations within 60s window
    }

    struct attack_correlation_record corr = {0};
    corr.timestamp = (int64_t)now;
    snprintf(corr.attack_type, sizeof(corr.attack_type), "%s", atk_label);
    if (network_event_id > 0 && security_event_id > 0) {
        corr.confidence_score = 0.95f;
    } else if (network_event_id > 0 || security_event_id > 0) {
        corr.confidence_score = 0.78f;
    } else {
        corr.confidence_score = 0.60f;
    }
    corr.network_event_id = network_event_id;
    corr.security_event_id = security_event_id;
    snprintf(corr.source_ip, sizeof(corr.source_ip), "%s", ip_buf);
    if (description && description[0]) {
        snprintf(corr.description, sizeof(corr.description), "%s", description);
    } else {
        snprintf(corr.description, sizeof(corr.description),
                 "Correlated %s from %s (PID %u)", atk_label, ip_buf, pid);
    }
    if (details && details[0]) {
        snprintf(corr.details, sizeof(corr.details), "%s", details);
    } else {
        snprintf(corr.details, sizeof(corr.details),
                 "pid=%u network_event_id=%lld security_event_id=%lld",
                 pid, (long long)network_event_id, (long long)security_event_id);
    }

    if (database_insert_attack_correlation(g_db, &corr) != 0) {
        return -1;
    }

    struct json_object *root = json_object_new_object();
    struct json_object *data = json_object_new_object();
    if (root && data) {
        json_object_object_add(data, "timestamp", json_object_new_int64(corr.timestamp));
        json_object_object_add(data, "attack_type", json_object_new_string(corr.attack_type));
        json_object_object_add(data, "confidence_score", json_object_new_double(corr.confidence_score));
        json_object_object_add(data, "network_event_id", json_object_new_int64(corr.network_event_id));
        json_object_object_add(data, "security_event_id", json_object_new_int64(corr.security_event_id));
        json_object_object_add(data, "source_ip", json_object_new_string(corr.source_ip));
        json_object_object_add(data, "description", json_object_new_string(corr.description));
        json_object_object_add(root, "type", json_object_new_string("correlation_alert"));
        json_object_object_add(root, "data", data);
        const char *j = json_object_to_json_string(root);
        if (j) ws_broadcast_message(j);
    } else {
        if (data) json_object_put(data);
    }
    if (root) json_object_put(root);

    return 0;
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
        if (strcmp(event.event_type, EVENT_TYPE_PROCESS_EXIT) == 0) {
            pthread_mutex_lock(&tetragon_state.stats_mutex);
            tetragon_state.stats.total_events++;
            tetragon_state.stats.process_exit_events++;
            pthread_mutex_unlock(&tetragon_state.stats_mutex);
            json_object_put(json_event);
            return 0;
        }

        // Store in database and capture row ID for correlation
        int64_t sec_id = 0;
        tetragon_store_event_ex(&event, &sec_id);

        // Generate alert immediately on warnings/criticals, coalesce INFO WS updates
        if (event.severity >= SEVERITY_WARNING) {
            tetragon_generate_alert(&event);
            api_security_invalidate_stats_cache();
        } else {
            queue_security_ws_update();
        }

        // Auto-correlate host security events with recent XDP network attacks or high-confidence exploits
        if (g_db && g_db->is_open && event.severity >= SEVERITY_WARNING) {
            time_t cutoff = time(NULL) - 300;
            int64_t net_id = 0;
            const char *corr_ip = NULL;

            if (event.src_ip[0]) {
                net_id = database_find_recent_attack_by_ip(g_db, event.src_ip, cutoff);
                if (net_id > 0) corr_ip = event.src_ip;
            }
            if (net_id == 0 && event.dst_ip[0]) {
                net_id = database_find_recent_attack_by_ip(g_db, event.dst_ip, cutoff);
                if (net_id > 0) corr_ip = event.dst_ip;
            }
            if (!corr_ip) {
                corr_ip = event.dst_ip[0] ? event.dst_ip : (event.src_ip[0] ? event.src_ip : "local");
            }

            if (net_id > 0 ||
                (event.severity >= SEVERITY_CRITICAL &&
                 (event.alert_type & (ALERT_RCE_ATTEMPT | ALERT_REVERSE_SHELL |
                                      ALERT_WEBSHELL_UPLOAD | ALERT_PRIVILEGE_ESCALATION |
                                      ALERT_CONTAINER_ESCAPE)))) {
                const char *corr_type = "HOST_NETWORK_CORRELATION";
                if (event.alert_type & ALERT_REVERSE_SHELL) corr_type = "REVERSE_SHELL_C2";
                else if (event.alert_type & ALERT_RCE_ATTEMPT) corr_type = "RCE_INTRUSION";
                else if (event.alert_type & ALERT_WEBSHELL_UPLOAD) corr_type = "WEBSHELL_EXPLOIT";
                else if (event.alert_type & ALERT_PRIVILEGE_ESCALATION) corr_type = "PRIVILEGE_ESCALATION";
                else if (event.alert_type & ALERT_FILE_INTEGRITY) corr_type = "FIM_BREACH";
                else if (event.alert_type & ALERT_CONTAINER_ESCAPE) corr_type = "CONTAINER_ESCAPE";

                char details[2048];
                snprintf(details, sizeof(details),
                         "process=%.128s binary=%.384s parent=%.384s file=%.384s policy=%.128s dst_port=%u",
                         event.process_name[0] ? event.process_name : "unknown",
                         event.binary_path,
                         event.parent_binary,
                         event.file_path,
                         event.policy_name[0] ? event.policy_name : "-",
                         (unsigned)event.dst_port);

                tetragon_correlate_events(corr_ip, event.pid, corr_type, net_id, sec_id,
                                          event.message, details);
            }
        }
        
        // Update stats
        pthread_mutex_lock(&tetragon_state.stats_mutex);
        tetragon_state.stats.total_events++;
        if (strcmp(event.event_type, EVENT_TYPE_PROCESS_EXEC) == 0) {
            tetragon_state.stats.process_exec_events++;
        }
        if (event.file_path[0]) {
            tetragon_state.stats.file_access_events++;
        }
        if (event.src_ip[0] || event.dst_ip[0]) {
            tetragon_state.stats.network_events++;
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
    char line[32768];
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
        flush_pending_security_ws_update(0);

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
