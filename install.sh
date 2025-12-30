#!/bin/bash

# Cyrenus DDoS Protection System - Installation Script
# This script handles dependency checking, compilation, and system setup

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
   ____                           
  / ___|   _  _ __  _ __  _ __   _   _ ___  
 | |  | | | || '__/ / _ \| '_ \ | | | / __| 
 | |__| |_| || |  |  __/ | | | || |_| \__ \ 
  \____\__, ||_|   \___| |_| |_| \__,_|___/ 
       |___/                                
  
  DDoS Protection System - Installation
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect Linux distribution${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $VER${NC}\n"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check kernel version
check_kernel_version() {
    echo -e "${BLUE}Checking kernel version...${NC}"
    kernel_version=$(uname -r | cut -d'.' -f1,2)
    required_version="5.8"
    
    if awk "BEGIN {exit !($kernel_version >= $required_version)}"; then
        echo -e "${GREEN}✓ Kernel version $kernel_version is supported${NC}"
        return 0
    else
        echo -e "${RED}✗ Kernel version $kernel_version is too old (requires >= 5.8)${NC}"
        return 1
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "\n${BLUE}Installing dependencies...${NC}\n"
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                build-essential \
                clang \
                llvm \
                libelf-dev \
                libbpf-dev \
                libmicrohttpd-dev \
                libconfig-dev \
                libjson-c-dev \
                libcurl4-openssl-dev \
                libwebsockets-dev \
                libssl-dev \
                libsqlcipher-dev \
                libmaxminddb-dev \
                libharu-dev \
                uuid-dev \
                pkg-config \
                git \
                curl \
                nodejs \
                npm
            ;;
        fedora|rhel|centos)
            dnf install -y \
                gcc \
                clang \
                llvm \
                elfutils-libelf-devel \
                libbpf-devel \
                libmicrohttpd-devel \
                libconfig-devel \
                json-c-devel \
                libcurl-devel \
                libwebsockets-devel \
                openssl-devel \
                sqlcipher-devel \
                libmaxminddb-devel \
                libharu-devel \
                libuuid-devel \
                pkgconfig \
                git \
                curl \
                nodejs \
                npm
            ;;
        arch)
            pacman -Sy --noconfirm \
                base-devel \
                clang \
                llvm \
                libelf \
                libbpf \
                libmicrohttpd \
                libconfig \
                json-c \
                curl \
                libwebsockets \
                openssl \
                sqlcipher \
                libmaxminddb \
                libharu \
                util-linux \
                pkgconf \
                git \
                nodejs \
                npm
            ;;
        *)
            echo -e "${YELLOW}Warning: Automatic dependency installation not supported for $OS${NC}"
            echo "Please install the following dependencies manually:"
            echo "  - clang, llvm"
            echo "  - libelf-dev, libbpf-dev"
            echo "  - libmicrohttpd-dev, libconfig-dev, libjson-c-dev"
            echo "  - libcurl-dev, libwebsockets-dev"
            echo "  - libsqlcipher-dev, libmaxminddb-dev, libharu-dev"
            echo "  - nodejs, npm"
            read -p "Press Enter to continue or Ctrl+C to abort..."
            ;;
    esac
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Function to verify dependencies
verify_dependencies() {
    echo -e "\n${BLUE}Verifying dependencies...${NC}"
    
    local missing_deps=()
    
    # Check for required commands
    for cmd in clang llvm-config pkg-config node npm; do
        if ! command_exists "$cmd"; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Check for required libraries
    for lib in bpf elf microhttpd config json-c curl websockets ssl crypto sqlcipher maxminddb uuid; do
        if ! pkg-config --exists "lib$lib" 2>/dev/null && ! ldconfig -p | grep -q "lib$lib"; then
            missing_deps+=("lib$lib")
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All dependencies verified${NC}"
        return 0
    else
        echo -e "${RED}✗ Missing dependencies: ${missing_deps[*]}${NC}"
        return 1
    fi
}

# Interactive configuration
configure_system() {
    echo -e "\n${BLUE}System Configuration${NC}\n"
    
    # Default values
    DEFAULT_INTERFACE=""
    DEFAULT_HTTP_PORT=8181
    DEFAULT_USERNAME="admin"
    DEFAULT_INSTALL_PATH="/usr/local/bin"
    
    # Detect available network interfaces
    echo -e "${YELLOW}Available network interfaces:${NC}"
    ip -o link show | awk -F': ' '{print "  - " $2}'
    echo ""
    
    read -p "Enter network interface to monitor [auto-detect]: " INTERFACE
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        echo "Auto-detected: $INTERFACE"
    fi
    
    read -p "Enter HTTP API port [$DEFAULT_HTTP_PORT]: " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-$DEFAULT_HTTP_PORT}
    
    read -p "Enter admin username [$DEFAULT_USERNAME]: " USERNAME
    USERNAME=${USERNAME:-$DEFAULT_USERNAME}
    
    echo ""
    read -s -p "Enter admin password: " PASSWORD
    echo ""
    read -s -p "Confirm admin password: " PASSWORD_CONFIRM
    echo ""
    
    if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
        echo -e "${RED}Passwords do not match!${NC}"
        exit 1
    fi
    
    # Generate app secret
    APP_SECRET=$(openssl rand -hex 32)
    
    # Generate database encryption key
    DB_KEY=$(openssl rand -hex 32)
    
    echo -e "\n${GREEN}Configuration saved${NC}"
}

# Create configuration files
create_config_files() {
    echo -e "\n${BLUE}Creating configuration files...${NC}"
    
    # Create /etc/cyrenus directory
    mkdir -p /etc/cyrenus
    
    # Create main configuration file
    cat > /etc/cyrenus/cyrenus.conf << EOF
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
    path = "/var/lib/cyrenus/cyrenus.db";
    encrypted = true;
};

# GeoIP settings
geoip = {
    database_path = "/var/lib/cyrenus/GeoLite2-Country.mmdb";
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
    echo "$DB_KEY" > /etc/cyrenus/master.key
    chmod 600 /etc/cyrenus/master.key
    
    # Create data directory
    mkdir -p /var/lib/cyrenus
    
    echo -e "${GREEN}✓ Configuration files created${NC}"
}

# Build the application
build_application() {
    echo -e "\n${BLUE}Building Cyrenus...${NC}\n"
    
    # Build embedded web UI
    if [ -d "web" ]; then
        echo "Building web UI..."
        cd web
        npm install
        npm run build
        ./build.sh 2>/dev/null || true
        cd ..
    fi
    
    # Build main application
    make clean
    make all
    
    echo -e "${GREEN}✓ Build completed${NC}"
}

# Run tests
run_tests() {
    echo -e "\n${BLUE}Running tests...${NC}"
    
    if make test 2>/dev/null; then
        echo -e "${GREEN}✓ All tests passed${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Tests not available or failed${NC}"
        return 0  # Don't fail installation
    fi
}

# Install the application
install_application() {
    echo -e "\n${BLUE}Installing Cyrenus...${NC}"
    
    # Install using Makefile
    make install
    
    # Create systemd service
    cat > /etc/systemd/system/cyrenus.service << EOF
[Unit]
Description=Cyrenus DDoS Protection System
After=network.target
Documentation=https://github.com/yourusername/cyrenus

[Service]
Type=simple
ExecStart=/usr/local/bin/cyrenus /etc/cyrenus/cyrenus.conf
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
ReadWritePaths=/var/lib/cyrenus

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}✓ Installation completed${NC}"
}

# Download GeoIP database
download_geoip() {
    echo -e "\n${BLUE}Downloading GeoIP database...${NC}"
    
    GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    GEOIP_PATH="/var/lib/cyrenus/GeoLite2-Country.mmdb"
    
    if curl -L -o "$GEOIP_PATH" "$GEOIP_URL"; then
        echo -e "${GREEN}✓ GeoIP database downloaded${NC}"
    else
        echo -e "${YELLOW}⚠ Failed to download GeoIP database${NC}"
        echo "You can download it manually from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    fi
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
    echo -e "  Config File:     /etc/cyrenus/cyrenus.conf"
    echo -e "  Database:        /var/lib/cyrenus/cyrenus.db"
    
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
    
    echo -e "\n${BLUE}Useful Commands:${NC}"
    echo -e "  Stop service:    ${YELLOW}sudo systemctl stop cyrenus${NC}"
    echo -e "  Restart service: ${YELLOW}sudo systemctl restart cyrenus${NC}"
    echo -e "  Uninstall:       ${YELLOW}sudo make uninstall${NC}"
    
    echo ""
}

# Main installation flow
main() {
    echo -e "${BLUE}Starting installation process...${NC}\n"
    
    # Step 1: Check kernel version
    if ! check_kernel_version; then
        echo -e "${RED}Aborting installation${NC}"
        exit 1
    fi
    
    # Step 2: Install dependencies
    echo ""
    read -p "Install system dependencies? (y/n) [y]: " INSTALL_DEPS
    INSTALL_DEPS=${INSTALL_DEPS:-y}
    
    if [[ "$INSTALL_DEPS" =~ ^[Yy] ]]; then
        install_dependencies
    fi
    
    # Step 3: Verify dependencies
    if ! verify_dependencies; then
        echo -e "${RED}Some dependencies are missing. Please install them manually.${NC}"
        exit 1
    fi
    
    # Step 4: Configure system
    configure_system
    
    # Step 5: Create configuration files
    create_config_files
    
    # Step 6: Build application
    build_application
    
    # Step 7: Run tests (optional)
    echo ""
    read -p "Run tests? (y/n) [y]: " RUN_TESTS
    RUN_TESTS=${RUN_TESTS:-y}
    
    if [[ "$RUN_TESTS" =~ ^[Yy] ]]; then
        run_tests
    fi
    
    # Step 8: Install application
    install_application
    
    # Step 9: Download GeoIP database
    download_geoip
    
    # Step 10: Print instructions
    print_instructions
}

# Run main installation
main
