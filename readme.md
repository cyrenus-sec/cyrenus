# Cyrenus

Cyrenus is a high-performance eBPF-based network traffic monitoring and DDoS protection system, seamlessly integrated with Tetragon for runtime security.

## Installation

### Option 1: Quick Install (Recommended)

The automated installer handles all dependencies, compilation, and Tetragon policy configuration.

```bash
sudo ./install.sh
```

Supported Distributions:
- Ubuntu/Debian
- RHEL/CentOS/Fedora
- Arch Linux

### Option 2: Docker Container

Cyrenus can be run as a containerized application.

**Build:**
```bash
docker build -t cyrenus .
```

**Run:**
```bash
docker run -d --name cyrenus \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --network host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  cyrenus
```

### Option 3: Manual Build

1.  **Install Dependencies** (See `install.sh` for list per distro).
2.  **Build:**
    ```bash
    make
    ```
3.  **Run:**
    ```bash
    sudo ./build/cyrenus -c config/cyrenus.conf
    ```

## Post-Installation

### 1. Configure Tetragon Policies
If you installed via `install.sh` or Docker, policies may already be applied. To apply manually:

```bash
# List active policies
sudo tetra tracingpolicy list

# Add policies
sudo tetra tracingpolicy add config/tetragon/policies/anti-rce.yaml
sudo tetra tracingpolicy add config/tetragon/policies/file-integrity.yaml
```

### 2. Verify Installation
Run the verification script to test security policies:

```bash
sudo bash tests/verify_policies.sh
```

## Features

- **DDoS Protection**: XDP-based packet filtering.
- **Tetragon Integration**: Runtime security for Anti-RCE and process monitoring.
- **Web Dashboard**: Real-time traffic analysis and control.

## Documentation
See `docs/` for architecture and API documentation.

## License
MIT
