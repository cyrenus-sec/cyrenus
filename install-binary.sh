#!/bin/bash

# Cyrenus DDoS Protection System - Binary Installation Script
# Fast installation using pre-built binaries from GitHub releases

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="cyrenus-sec/cyrenus"
INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/local/lib"
CONFIG_DIR="/etc/cyrenus"
DATA_DIR="/var/lib/cyrenus"

# Banner
echo -e "${BLUE}"
cat <<"EOF"
   ____                           
  / ___|   _  _ __  _ __  _ __   _   _ ___  
 | |  | | | || '__/ / _ \| '_ \ | | | / __| 
 | |__| |_| || |  |  __/ | | | || |_| \__ \ 
  \____\__, ||_|   \___| |_| |_| \__,_|___/ v2.0.0
       |___/                                
  
  DDoS Protection System - Binary Installation
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect Linux distribution${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $VER${NC}\n"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH_SUFFIX="amd64"
        ;;
    aarch64|arm64)
        ARCH_SUFFIX="arm64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}Architecture: $ARCH_SUFFIX${NC}\n"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check kernel version (eBPF XDP requires >= 5.8)
check_kernel_version() {
    echo -e "${BLUE}Checking kernel version...${NC}"
    local major minor
    IFS='.' read -r major minor _ <<< "$(uname -r)"
    minor="${minor%%[^0-9]*}"
    if [ -n "$major" ] && [ -n "$minor" ] && { [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 8 ]; }; }; then
        echo -e "${GREEN}✓ Kernel version ${major}.${minor} is supported${NC}\n"
    else
        echo -e "${RED}✗ Kernel version $(uname -r) is too old (requires >= 5.8)${NC}"
        exit 1
    fi
}

# Resolve first available Debian/Ubuntu package name among SONAME alternatives
resolve_deb_pkg() {
    local pkg candidate
    for pkg in "$@"; do
        candidate=$(LC_ALL=C apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}' || true)
        if [ -n "$candidate" ] && [ "$candidate" != "(none)" ]; then
            echo "$pkg"
            return 0
        fi
    done
    return 1
}

# Install minimal runtime dependencies
install_runtime_deps() {
    echo -e "${BLUE}Installing runtime dependencies...${NC}\n"
    
    case $OS in
        ubuntu|debian)
            apt-get update
            local deb_pkgs=(curl ca-certificates tar iproute2 openssl)
            local spec pkg
            for spec in \
                "libelf1t64 libelf1" \
                "libbpf1 libbpf0" \
                "libmicrohttpd12t64 libmicrohttpd12" \
                "libconfig9 libconfig11" \
                "libjson-c5 libjson-c4" \
                "libcurl4t64 libcurl4" \
                "libwebsockets19t64 libwebsockets17 libwebsockets16" \
                "libssl3t64 libssl3" \
                "libsqlcipher1 libsqlcipher0" \
                "libmaxminddb0" \
                "libuuid1" \
                "zlib1g"; do
                # shellcheck disable=SC2086
                if pkg=$(resolve_deb_pkg $spec); then
                    deb_pkgs+=("$pkg")
                fi
            done
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${deb_pkgs[@]}"
            ;;
        fedora|rhel|centos)
            dnf install -y \
                curl \
                ca-certificates \
                tar \
                iproute \
                openssl \
                elfutils-libelf \
                libbpf \
                libmicrohttpd \
                libconfig \
                json-c \
                libcurl \
                libwebsockets \
                sqlcipher \
                libmaxminddb \
                libuuid \
                zlib
            ;;
        arch)
            pacman -Sy --noconfirm \
                curl \
                ca-certificates \
                tar \
                iproute2 \
                openssl \
                libelf \
                libbpf \
                libmicrohttpd \
                libconfig \
                json-c \
                libwebsockets \
                sqlcipher \
                libmaxminddb \
                util-linux-libs \
                zlib
            ;;
        *)
            echo -e "${YELLOW}Unknown distribution ($OS), skipping dependency installation${NC}"
            ;;
    esac
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Get release version (supports CYRENUS_VERSION env override)
get_latest_release() {
    if [ -n "${CYRENUS_VERSION:-}" ]; then
        LATEST="$CYRENUS_VERSION"
        echo -e "${GREEN}Using requested version: $LATEST${NC}"
        return
    fi

    echo -e "${BLUE}Fetching latest release...${NC}"
    
    # Try to get latest release from GitHub API
    if command_exists curl; then
        LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
        
        if [ -z "$LATEST" ]; then
            # Fallback to current release if API fails or is rate-limited
            LATEST="v2.0.0"
            echo -e "${YELLOW}Could not fetch latest release, using default: $LATEST${NC}"
        else
            echo -e "${GREEN}Latest version: $LATEST${NC}"
        fi
    else
        echo -e "${RED}curl not found${NC}"
        exit 1
    fi
}

# Download and extract release archive
download_binaries() {
    echo -e "\n${BLUE}Downloading Cyrenus binaries...${NC}"
    
    ARCHIVE_NAME="cyrenus-${LATEST}-linux-${ARCH_SUFFIX}.tar.gz"
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST/$ARCHIVE_NAME"
    
    # Create temporary directory with automatic cleanup
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "${TMP_DIR:-}"' EXIT
    
    echo "Downloading from: $DOWNLOAD_URL"
    
    if curl -fL -o "$TMP_DIR/$ARCHIVE_NAME" "$DOWNLOAD_URL"; then
        echo -e "${GREEN}✓ Download complete${NC}"
    else
        echo -e "${RED}Failed to download binaries${NC}"
        echo -e "${YELLOW}The release might not exist yet. Please build from source using ./install.sh${NC}"
        exit 1
    fi
    
    # Verify SHA256 checksum if published alongside the tarball
    if curl -fsSL -o "$TMP_DIR/${ARCHIVE_NAME}.sha256" "${DOWNLOAD_URL}.sha256" 2>/dev/null; then
        if (cd "$TMP_DIR" && sha256sum -c "${ARCHIVE_NAME}.sha256"); then
            echo -e "${GREEN}✓ Checksum verified${NC}"
        else
            echo -e "${RED}SHA256 checksum verification failed!${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}⚠ No .sha256 checksum file found for $ARCHIVE_NAME; skipping verification${NC}"
    fi
    
    # Extract safely regardless of whether the archive wraps a subdirectory or is flat
    echo "Extracting files..."
    mkdir -p "$TMP_DIR/extract"
    tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR/extract"
    
    BIN_CYRENUS=$(find "$TMP_DIR/extract" -maxdepth 2 -type f -name cyrenus | head -n1)
    OBJ_XDP=$(find "$TMP_DIR/extract" -maxdepth 2 -type f -name xdp_prog.o | head -n1)
    
    if [ -z "$BIN_CYRENUS" ] || [ -z "$OBJ_XDP" ]; then
        echo -e "${RED}Error: Downloaded archive does not contain 'cyrenus' and 'xdp_prog.o'${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Files extracted${NC}"
}

# Install binaries
install_binaries() {
    echo -e "\n${BLUE}Installing binaries...${NC}"
    
    # Verify binary links against this host's shared libraries before replacing system files
    chmod +x "$BIN_CYRENUS"
    if ! "$BIN_CYRENUS" --version >/dev/null 2>&1; then
        echo -e "${RED}Error: Pre-built binary is incompatible with this host's shared libraries or glibc.${NC}"
        echo -e "${YELLOW}Details:${NC}"
        ldd "$BIN_CYRENUS" 2>&1 | grep -E "not found|version" || "$BIN_CYRENUS" --version 2>&1 || true
        echo -e "${YELLOW}Please build from source for this OS/distro using: sudo ./install.sh${NC}"
        exit 1
    fi
    
    mkdir -p "$INSTALL_DIR" "$LIB_DIR"
    
    # Install main binary
    install -m 755 "$BIN_CYRENUS" "$INSTALL_DIR/cyrenus"
    echo "Installed: $INSTALL_DIR/cyrenus ($("$INSTALL_DIR/cyrenus" --version | head -n1))"
    
    # Install eBPF object
    install -m 644 "$OBJ_XDP" "$LIB_DIR/cyrenus_xdp_prog.o"
    echo "Installed: $LIB_DIR/cyrenus_xdp_prog.o"
    
    echo -e "${GREEN}✓ Binaries installed${NC}"
}

# Interactive configuration
configure_system() {
    echo -e "\n${BLUE}System Configuration${NC}\n"
    
    # Detect available network interfaces
    echo -e "${YELLOW}Available network interfaces:${NC}"
    ip -o link show | awk -F': ' '{print "  - " $2}'
    echo ""
    
    read -p "Enter network interface to monitor [auto-detect]: " INTERFACE </dev/tty
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip route | awk '/^default/ {print $5; exit}')
        if [ -z "$INTERFACE" ]; then
            INTERFACE=$(ip -o link show up | awk -F': ' '$2 != "lo" {sub(/@.*/, "", $2); print $2; exit}')
        fi
        echo "Auto-detected: $INTERFACE"
    fi
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}Error: Could not auto-detect an active network interface${NC}"
        exit 1
    fi
    
    read -p "Enter HTTP API port [8181]: " HTTP_PORT </dev/tty
    HTTP_PORT=${HTTP_PORT:-8181}
    
    read -p "Enter admin username [admin]: " USERNAME </dev/tty
    USERNAME=${USERNAME:-admin}
    
    echo ""
    read -s -p "Enter admin password: " PASSWORD </dev/tty
    echo ""
    read -s -p "Confirm admin password: " PASSWORD_CONFIRM </dev/tty
    echo ""
    
    if [ -z "$PASSWORD" ]; then
        echo -e "${RED}Password cannot be empty!${NC}"
        exit 1
    fi
    if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
        echo -e "${RED}Passwords do not match!${NC}"
        exit 1
    fi
    
    # Generate secrets
    APP_SECRET=$(openssl rand -hex 32)
    DB_KEY=$(openssl rand -hex 32)
    
    echo -e "\n${GREEN}Configuration saved${NC}"
}

# Create configuration files
create_config_files() {
    echo -e "\n${BLUE}Creating configuration files...${NC}"
    
    # Create directories
    mkdir -p "$CONFIG_DIR" "$DATA_DIR" /etc/tetragon/policies /var/log/tetragon
    chmod 755 "$DATA_DIR" /etc/tetragon /etc/tetragon/policies /var/log/tetragon
    
    # Create main configuration file
    cat > "$CONFIG_DIR/cyrenus.conf" <<EOF
# Cyrenus Configuration File
# Generated on $(date)

# Network interface to monitor
interface = "$INTERFACE";

# HTTP API server port
http_port = $HTTP_PORT;

# Backend integration (optional)
backend = {
    url = "http://localhost";
    api_key = "";
    api_secret = "";
};

# Authentication
username = "$USERNAME";
password = "$PASSWORD";
app_secret = "$APP_SECRET";

# Database settings
database = {
    path = "$DATA_DIR/cyrenus.db";
    encrypted = true;
};

# GeoIP settings
geoip = {
    database_path = "$DATA_DIR/GeoLite2-Country.mmdb";
    auto_update = true;
};

# Notification settings
notifications = {
    email = {
        enabled = false;
        smtp_server = "";
        smtp_port = 587;
        from_address = "";
        to_addresses = [];
    };
    slack = {
        enabled = false;
        webhook_url = "";
    };
};

# Attack detection thresholds
detection = {
    syn_flood_rate = 500;
    synack_flood_rate = 1000;
    rst_flood_rate = 500;
    ack_flood_rate = 2500;
    udp_flood_rate = 5000;
    icmp_flood_rate = 100;
    dns_amp_rate = 200;
    max_frags = 15;
    max_dns_response_size = 2048;
    global_syn_rate = 5000;
    global_udp_rate = 25000;
    auto_block_enabled = 1;
    auto_block_duration_sec = 300;
};
EOF

    chmod 600 "$CONFIG_DIR/cyrenus.conf"

    # Create database encryption key file
    echo "$DB_KEY" > "$CONFIG_DIR/master.key"
    chmod 600 "$CONFIG_DIR/master.key"
    
    echo -e "${GREEN}✓ Configuration files created${NC}"
}

# Download GeoIP database
download_geoip() {
    echo -e "\n${BLUE}Downloading GeoIP database...${NC}"
    
    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    GEOIP_PATH="$DATA_DIR/GeoLite2-Country.mmdb"
    
    if curl -fsSL -o "$GEOIP_PATH" "$GEOIP_URL"; then
        echo -e "${GREEN}✓ GeoIP database downloaded${NC}"
    else
        echo -e "${YELLOW}⚠ Failed to download GeoIP database${NC}"
    fi
}

# Create systemd service
create_service() {
    echo -e "\n${BLUE}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/cyrenus.service <<EOF
[Unit]
Description=Cyrenus DDoS Protection System
After=network.target
Documentation=https://github.com/cyrenus-sec/cyrenus

[Service]
Type=simple
ExecStart=$INSTALL_DIR/cyrenus $CONFIG_DIR/cyrenus.conf
Restart=on-failure
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=true
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR /etc/tetragon /etc/tetragon/policies

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    echo -e "${GREEN}✓ Systemd service created${NC}"
}

# Print final instructions
print_instructions() {
    echo -e "\n${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Cyrenus Installation Completed Successfully!  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "  Interface:       $INTERFACE"
    echo -e "  HTTP API Port:   $HTTP_PORT"
    echo -e "  Admin Username:  $USERNAME"
    echo -e "  Config File:     $CONFIG_DIR/cyrenus.conf"
    echo -e "  Database:        $DATA_DIR/cyrenus.db"
    
    echo -e "\n${BLUE}Next Steps:${NC}"
    echo -e "  1. Start the service:"
    echo -e "     ${YELLOW}sudo systemctl start cyrenus${NC}"
    echo -e ""
    echo -e "  2. Enable auto-start on boot:"
    echo -e "     ${YELLOW}sudo systemctl enable cyrenus${NC}"
    echo -e ""
    echo -e "  3. Check status:"
    echo -e "     ${YELLOW}sudo systemctl status cyrenus${NC}"
    echo -e ""
    echo -e "  4. Access the web dashboard:"
    echo -e "     ${YELLOW}http://localhost:$HTTP_PORT${NC}"
    echo -e ""
    echo -e "  5. View logs:"
    echo -e "     ${YELLOW}sudo journalctl -u cyrenus -f${NC}"
    
    echo ""
}

# Main installation flow
main() {
    check_kernel_version
    install_runtime_deps
    get_latest_release
    download_binaries
    install_binaries
    configure_system
    create_config_files
    download_geoip
    create_service
    
    print_instructions
}

# Run main installation
main
