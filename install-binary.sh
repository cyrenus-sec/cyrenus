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
  \____\__, ||_|   \___| |_| |_| \__,_|___/ v.0.1
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

# Install minimal runtime dependencies
install_runtime_deps() {
    echo -e "${BLUE}Installing runtime dependencies...${NC}\n"
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl ca-certificates
            ;;
        fedora|rhel|centos)
            dnf install -y curl ca-certificates
            ;;
        arch)
            pacman -Sy --noconfirm curl ca-certificates
            ;;
        *)
            echo -e "${YELLOW}Unknown distribution, skipping dependency installation${NC}"
            ;;
    esac
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Get latest release version
get_latest_release() {
    echo -e "${BLUE}Fetching latest release...${NC}"
    
    # Try to get latest release from GitHub API
    if command_exists curl; then
        LATEST=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        
        if [ -z "$LATEST" ]; then
            # Fallback to v1.0.0 if API fails
            LATEST="v1.0.0"
            echo -e "${YELLOW}Could not fetch latest release, using default: $LATEST${NC}"
        else
            echo -e "${GREEN}Latest version: $LATEST${NC}"
        fi
    else
        echo -e "${RED}curl not found${NC}"
        exit 1
    fi
}

# Download binaries
download_binaries() {
    echo -e "\n${BLUE}Downloading Cyrenus binaries...${NC}"
    
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST/cyrenus-${LATEST}-linux-${ARCH_SUFFIX}.tar.gz"
    
    # Create temporary directory
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"
    
    echo "Downloading from: $DOWNLOAD_URL"
    
    if curl -L -f -o cyrenus.tar.gz "$DOWNLOAD_URL"; then
        echo -e "${GREEN}✓ Download complete${NC}"
    else
        echo -e "${RED}Failed to download binaries${NC}"
        echo -e "${YELLOW}The release might not exist yet. Please build from source using ./install.sh${NC}"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    
    # Extract
    echo "Extracting files..."
    tar -xzf cyrenus.tar.gz
    
    echo -e "${GREEN}✓ Files extracted${NC}"
}

# Install binaries
install_binaries() {
    echo -e "\n${BLUE}Installing binaries...${NC}"
    
    # Install main binary
    install -m 755 cyrenus "$INSTALL_DIR/cyrenus"
    echo "Installed: $INSTALL_DIR/cyrenus"
    
    # Install eBPF object
    install -m 644 xdp_prog.o "$LIB_DIR/cyrenus_xdp_prog.o"
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
    
    read -p "Enter network interface to monitor [auto-detect]: " INTERFACE
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        echo "Auto-detected: $INTERFACE"
    fi
    
    read -p "Enter HTTP API port [8181]: " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-8181}
    
    read -p "Enter admin username [admin]: " USERNAME
    USERNAME=${USERNAME:-admin}
    
    echo ""
    read -s -p "Enter admin password: " PASSWORD
    echo ""
    read -s -p "Confirm admin password: " PASSWORD_CONFIRM
    echo ""
    
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
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p /etc/tetragon/policies
    
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
    syn_flood_threshold = 1000;      # packets per second
    udp_flood_threshold = 5000;      # packets per second
    dns_amplification_ratio = 10.0;  # response/request size ratio
    auto_blacklist_threshold = 3;    # number of attacks before auto-block
};
EOF

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
    
    if curl -L -o "$GEOIP_PATH" "$GEOIP_URL"; then
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
ReadWritePaths=$DATA_DIR

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
    install_runtime_deps
    get_latest_release
    download_binaries
    install_binaries
    configure_system
    create_config_files
    download_geoip
    create_service
    
    # Cleanup
    cd /
    rm -rf "$TMP_DIR"
    
    print_instructions
}

# Run main installation
main
