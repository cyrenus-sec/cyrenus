# Tetragon Integration for Cyrenus

This document describes the Tetragon eBPF security observability integration with Cyrenus.

## Overview

Tetragon provides runtime security monitoring and enforcement at the kernel level, complementing Cyrenus's network-layer protection with application-layer security.

### Key Features

- **Anti-RCE Protection**: Detects and blocks remote code execution attempts
- **Process Monitoring**: Tracks process execution, exits, and privilege changes
- **File Integrity Monitoring**: Monitors access to sensitive files
- **Attack Correlation**: Links network and process events for comprehensive threat detection

## Installation

### Prerequisites

- Linux kernel 5.8 or later
- Root access
- curl, jq, systemctl

### Install Tetragon

```bash
cd /home/moh/Documents/cyrenus
sudo ./scripts/install_tetragon.sh
```

This will:
1. Download and install Tetragon binaries
2. Create systemd service
3. Set up configuration and logging directories

### Deploy Policies

Copy the policies to Tetragon's policy directory:

```bash
sudo cp config/tetragon/policies/*.yaml /etc/tetragon/policies/
```

### Start Tetragon

```bash
sudo systemctl start tetragon
sudo systemctl enable tetragon  # Enable on boot
```

### Verify Installation

```bash
# Check service status
sudo systemctl status tetragon

# Check policies are loaded
sudo tetra tracingpolicy list

# View events (optional)
sudo tail -f /var/log/tetragon/tetragon.log
```

## Security Policies

### 1. Anti-RCE Policy (`anti-rce.yaml`)

Protects against remote code execution with 10 detection mechanisms:

- **Web server shell spawning**: Blocks shells launched from nginx/apache
- **Reverse shells**: Detects shells making outbound connections
- **Fileless attacks**: Prevents execution from `/tmp`, `/dev/shm`
- **Suspicious interpreters**: Monitors python/perl/php spawned by web servers
- **Privilege escalation**: Detects `setuid(0)` attempts
- **LD_PRELOAD attacks**: Blocks library injection
- **Attack tools**: Monitors nmap, metasploit, sqlmap
- **Bind shells**: Detects shells listening on ports
- **Process injection**: Monitors ptrace attach
- **Encoded commands**: Blocks base64-encoded command execution

**Actions**: Most rules use `Sigkill` (immediate termination) for critical threats.

### 2. Process Monitoring Policy (`process-monitoring.yaml`)

Tracks process lifecycle and security events:

- All process executions with full command line
- Process exits and exit codes
- SUID/SGID binary execution
- Credential/capability changes
- Namespace operations (container escapes)
- Process name changes
- Fork events (fork bomb detection)
- Core dumps (exploitation indicators)
- Kernel module loading
- eBPF program loading
- Executable memory allocation (code injection)

**Actions**: Monitoring mode (`Post`) - logs events without blocking.

### 3. File Integrity Monitoring Policy (`file-integrity.yaml`)

Monitors sensitive file access:

- `/etc` directory writes (configuration changes)
- Binary modifications (`/usr/bin`, `/sbin`)
- SSH key access
- Web directory writes (webshell detection)
- Script creation in `/tmp`
- Sensitive log access
- Cron file modifications (persistence)
- Systemd service changes (persistence)
- `/etc/passwd` and `/etc/shadow` access
- LD_PRELOAD configuration changes (rootkit indicator)

**Actions**: Monitoring mode - alerts on suspicious activity.

## Configuration

### Tetragon Configuration

Located at: `/etc/tetragon/tetragon.yaml`

Key settings:
- **export-filename**: `/var/log/tetragon/tetragon.log`
- **log-format**: `json`
- **tracing-policy-dir**: `/etc/tetragon/policies/`
- **metrics-server**: `:9090` (Prometheus metrics)

### Cyrenus Integration

Cyrenus automatically:
1. Monitors Tetragon log file using `inotify`
2. Parses JSON events
3. Stores events in `security_events` table
4. Generates real-time alerts via WebSocket
5. Correlates with network attacks

## Database Schema

### `security_events` Table

Stores all Tetragon events:

```sql
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity INTEGER NOT NULL,  -- 1=info, 2=warning, 3=error, 4=critical
    process_name TEXT,
    pid INTEGER,
    ppid INTEGER,
    uid INTEGER,
    command TEXT,
    binary_path TEXT,
    parent_binary TEXT,
    action TEXT,                 -- allow, block, Sigkill
    policy_name TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    file_path TEXT,
    file_operation TEXT,
    metadata TEXT,
    created_at INTEGER
);
```

### `attack_correlation` Table

Links network and process events:

```sql
CREATE TABLE attack_correlation (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    attack_type TEXT NOT NULL,
    confidence_score REAL,
    network_event_id INTEGER,
    security_event_id INTEGER,
    description TEXT,
    source_ip TEXT,
    details TEXT,
    created_at INTEGER
);
```

## API Endpoints

*Coming soon - security event API endpoints will be implemented in the next phase.*

Expected endpoints:
- `GET /api/security/events` - List security events
- `GET /api/security/stats` - Security statistics
- `GET /api/security/policies` - List policies
- `GET /api/security/correlation` - Attack correlations

## Monitoring

### View Tetragon Logs

```bash
# Raw JSON events
sudo tail -f /var/log/tetragon/tetragon.log | jq '.'

# Filter by severity
sudo cat /var/log/tetragon/tetragon.log | jq 'select(.process_kprobe.message | contains("CRITICAL"))'
```

### Check Cyrenus Integration

```bash
# Check if Tetragon monitor is running
ps aux | grep tetragon_event_monitor

# View Cyrenus logs
journalctl -u cyrenus -f
```

### Database Queries

```sql
-- Recent critical alerts
SELECT * FROM security_events WHERE severity = 4 ORDER BY timestamp DESC LIMIT 10;

-- Events blocked
SELECT COUNT(*) FROM security_events WHERE action IN ('Sigkill', 'block');

-- Top attacked processes
SELECT binary_path, COUNT(*) as count 
FROM security_events 
WHERE severity >= 3 
GROUP BY binary_path 
ORDER BY count DESC 
LIMIT 10;

-- Correlated attacks
SELECT * FROM attack_correlation WHERE confidence_score > 0.7 ORDER BY timestamp DESC;
```

## Performance Considerations

- **CPU Overhead**: Tetragon typically adds 1-5% CPU overhead
- **Combined with XDP**: Total overhead may reach 5-10%
- **Event Rate**: Process monitoring can generate high event volumes
- **Disk Usage**: JSON logs are rotated automatically every hour

## Troubleshooting

### Tetragon Not Starting

```bash
# Check kernel version
uname -r  # Must be 5.8+

# Check for errors
journalctl -u tetragon -n 50

# Verify BTF is available
ls /sys/kernel/btf/vmlinux
```

### No Events in Cyrenus

```bash
# Check Tetragon is generating events
sudo tail -f /var/log/tetragon/tetragon.log

# Check Cyrenus monitor
ps aux | grep cyrenus
journalctl -u cyrenus | grep -i tetragon
```

### High CPU Usage

```bash
# Check event rate
sudo cat /var/log/tetragon/tetragon.log | wc -l

# Disable process-monitoring policy temporarily
sudo rm /etc/tetragon/policies/process-monitoring.yaml
sudo systemctl restart tetragon
```

## Security Recommendations

1. **Start in Monitoring Mode**: Let policies run for 24-48 hours to establish baseline
2. **Review False Positives**: Check logs for legitimate activity being flagged
3. **Tune Policies**: Whitelist known-good processes
4. **Enable Blocking Gradually**: Start with anti-rce, then expand
5. **Monitor Performance**: Watch CPU/disk usage over time
6. **Set Retention Policies**: Clean old events to save disk space

## Example: Custom Policy

Create a custom policy to monitor database access:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: database-monitoring
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values:
        - "/usr/bin/mysql"
        - "/usr/bin/psql"
      matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "3306"  # MySQL
        - "5432"  # PostgreSQL
      matchActions:
      - action: Post
      message: "Non-database process connecting to database port"
```

Save to `/etc/tetragon/policies/database-monitoring.yaml` and restart Tetragon.

## Further Reading

- [Tetragon Documentation](https://tetragon.io/docs/)
- [Cilium eBPF Guide](https://ebpf.io/)
- [Tetragon Policy Examples](https://github.com/cilium/tetragon/tree/main/examples)
- [eBPF Security](https://isovalent.com/blog/tag/security/)

## Support

For issues with:
- **Tetragon**: https://github.com/cilium/tetragon/issues
- **Cyrenus Integration**: Check project documentation or repository issues
