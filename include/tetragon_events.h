#ifndef TETRAGON_EVENTS_H
#define TETRAGON_EVENTS_H

#include <stdint.h>
#include <json-c/json.h>
#include <pthread.h>

// Event types from Tetragon
#define EVENT_TYPE_PROCESS_EXEC         "PROCESS_EXEC"
#define EVENT_TYPE_PROCESS_EXIT         "PROCESS_EXIT"
#define EVENT_TYPE_PROCESS_KPROBE       "PROCESS_KPROBE"
#define EVENT_TYPE_PROCESS_TRACEPOINT   "PROCESS_TRACEPOINT"

// Event severity levels
#define SEVERITY_INFO       1
#define SEVERITY_WARNING    2
#define SEVERITY_ERROR      3
#define SEVERITY_CRITICAL   4

// Alert classifications
#define ALERT_RCE_ATTEMPT           0x0001
#define ALERT_PRIVILEGE_ESCALATION  0x0002
#define ALERT_FILE_INTEGRITY        0x0004
#define ALERT_PROCESS_INJECTION     0x0008
#define ALERT_REVERSE_SHELL         0x0010
#define ALERT_WEBSHELL_UPLOAD       0x0020
#define ALERT_PERSISTENCE           0x0040
#define ALERT_CONTAINER_ESCAPE      0x0080

// Maximum sizes
#define MAX_PROCESS_NAME    256
#define MAX_COMMAND_LINE    2048
#define MAX_FILE_PATH       4096
#define MAX_MESSAGE         1024
#define MAX_POLICY_NAME     128

// Process execution event
struct process_exec_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    char process_name[MAX_PROCESS_NAME];
    char binary_path[MAX_FILE_PATH];
    char parent_binary[MAX_FILE_PATH];
    char command_line[MAX_COMMAND_LINE];
    uint32_t caps_permitted;
    uint32_t caps_effective;
};

// File access event
struct file_event {
    uint64_t timestamp;
    uint32_t pid;
    char process_name[MAX_PROCESS_NAME];
    char file_path[MAX_FILE_PATH];
    char operation[32];  // read, write, execute, open
    uint32_t flags;
};

// Network connection event
struct network_event {
    uint64_t timestamp;
    uint32_t pid;
    char process_name[MAX_PROCESS_NAME];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

// Generic security event structure
struct security_event {
    uint64_t timestamp;
    char event_type[64];
    uint8_t severity;
    uint32_t alert_type;  // bitfield of ALERT_* flags
    
    // Process info
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char process_name[MAX_PROCESS_NAME];
    char command[MAX_COMMAND_LINE];
    char binary_path[MAX_FILE_PATH];
    char parent_binary[MAX_FILE_PATH];
    
    // Action taken
    char action[32];  // allow, block, alert, kill
    char policy_name[MAX_POLICY_NAME];
    
    // Additional context
    char message[MAX_MESSAGE];
    
    // Network context (if applicable)
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    
    // File context (if applicable)
    char file_path[MAX_FILE_PATH];
    char file_operation[32];
    
    // Metadata (JSON string for extensibility)
    char *metadata_json;
};

// Statistics
struct tetragon_stats {
    uint64_t total_events;
    uint64_t process_exec_events;
    uint64_t process_exit_events;
    uint64_t file_access_events;
    uint64_t network_events;
    uint64_t alerts_generated;
    uint64_t events_blocked;
    uint64_t last_update_time;
};

// Configuration
struct tetragon_config {
    char log_file_path[MAX_FILE_PATH];
    char policy_dir[MAX_FILE_PATH];
    int monitoring_enabled;
    int enforcement_enabled;
    int correlation_enabled;
    int alert_threshold_critical;
    int alert_threshold_warning;
};

// Initialize Tetragon event monitoring
int tetragon_init(const char *log_file_path);

// Start the event monitor thread
int tetragon_start_monitor(void);

// Stop the event monitor
void tetragon_stop_monitor(void);

// Get current statistics
int tetragon_get_stats(struct tetragon_stats *stats);

// Parse Tetragon JSON event
int tetragon_parse_event(struct json_object *json_event, struct security_event *event);

// Classify event severity based on content
uint8_t tetragon_classify_severity(const char *function_name, const char *message);

// Classify alert type based on event content
uint32_t tetragon_classify_alert_type(const char *message, const char *binary_path);

// Store event in database
int tetragon_store_event(struct security_event *event);

// Correlate network and process events
int tetragon_correlate_events(uint32_t src_ip, uint32_t pid, 
                               uint64_t network_event_id, uint64_t security_event_id);

// Generate alert for critical events
int tetragon_generate_alert(struct security_event *event);

// Get recent security events
int tetragon_get_recent_events(struct security_event **events, int limit, 
                                uint8_t min_severity);

// Cleanup
void tetragon_cleanup(void);

// Event monitor thread function
void *tetragon_event_monitor_thread(void *arg);

// Process a single JSON line from Tetragon log
int tetragon_process_json_line(const char *json_line);

// Check if Tetragon is running
int tetragon_is_running(void);

#endif // TETRAGON_EVENTS_H
