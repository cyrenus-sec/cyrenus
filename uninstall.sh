#!/bin/bash

# Cyrenus DDoS Protection System - Uninstallation Script
# This script removes Cyrenus and all its configuration files

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat <<"EOF"
   ____                           
  / ___|   _  _ __  _ __  _ __   _   _ ___  
 | |  | | | || '__/ / _ \| '_ \ | | | / __| 
 | |__| |_| || |  |  __/ | | | || |_| \__ \ 
  \____\__, ||_|   \___| |_| |_| \__,_|___/ 
       |___/                                
  
  DDoS Protection System - Uninstallation
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

# Confirmation prompt
echo -e "${YELLOW}WARNING: This will remove Cyrenus and all its data!${NC}"
echo -e "The following will be removed:"
echo -e "  - Cyrenus binaries"
echo -e "  - Systemd service"
echo -e "  - Configuration files in /etc/cyrenus"
echo -e "  - Database and data in /var/lib/cyrenus"
echo -e "  - Tetragon policies (if requested)"
echo ""
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo -e "${BLUE}Uninstallation cancelled.${NC}"
    exit 0
fi

echo -e "\n${BLUE}Starting uninstallation process...${NC}\n"

# Step 1: Stop and disable the service
echo -e "${BLUE}Stopping Cyrenus service...${NC}"
if systemctl is-active --quiet cyrenus; then
    systemctl stop cyrenus
    echo -e "${GREEN}✓ Service stopped${NC}"
else
    echo -e "${YELLOW}⚠ Service is not running${NC}"
fi

if systemctl is-enabled --quiet cyrenus 2>/dev/null; then
    systemctl disable cyrenus
    echo -e "${GREEN}✓ Service disabled${NC}"
else
    echo -e "${YELLOW}⚠ Service is not enabled${NC}"
fi

# Step 2: Remove systemd service file
echo -e "\n${BLUE}Removing systemd service...${NC}"
if [ -f /etc/systemd/system/cyrenus.service ]; then
    rm -f /etc/systemd/system/cyrenus.service
    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd service removed${NC}"
else
    echo -e "${YELLOW}⚠ Systemd service file not found${NC}"
fi

# Step 3: Remove binaries
echo -e "\n${BLUE}Removing installed binaries...${NC}"
if [ -f /usr/local/bin/cyrenus ]; then
    rm -f /usr/local/bin/cyrenus
    echo -e "${GREEN}✓ Binary removed from /usr/local/bin${NC}"
else
    echo -e "${YELLOW}⚠ Binary not found in /usr/local/bin${NC}"
fi

if [ -f /usr/local/lib/cyrenus_xdp_prog.o ]; then
    rm -f /usr/local/lib/cyrenus_xdp_prog.o
    echo -e "${GREEN}✓ eBPF program removed from /usr/local/lib${NC}"
else
    echo -e "${YELLOW}⚠ eBPF program not found in /usr/local/lib${NC}"
fi

# Step 4: Remove configuration directory
echo -e "\n${BLUE}Removing configuration files...${NC}"
read -p "Remove configuration directory /etc/cyrenus? (y/n) [y]: " REMOVE_CONFIG
REMOVE_CONFIG=${REMOVE_CONFIG:-y}

if [[ "$REMOVE_CONFIG" =~ ^[Yy] ]]; then
    if [ -d /etc/cyrenus ]; then
        rm -rf /etc/cyrenus
        echo -e "${GREEN}✓ Configuration directory removed${NC}"
    else
        echo -e "${YELLOW}⚠ Configuration directory not found${NC}"
    fi
else
    echo -e "${BLUE}Configuration kept in /etc/cyrenus${NC}"
fi

# Step 5: Remove data directory
echo -e "\n${BLUE}Removing data directory...${NC}"
read -p "Remove data directory /var/lib/cyrenus (includes database)? (y/n) [y]: " REMOVE_DATA
REMOVE_DATA=${REMOVE_DATA:-y}

if [[ "$REMOVE_DATA" =~ ^[Yy] ]]; then
    if [ -d /var/lib/cyrenus ]; then
        rm -rf /var/lib/cyrenus
        echo -e "${GREEN}✓ Data directory removed${NC}"
    else
        echo -e "${YELLOW}⚠ Data directory not found${NC}"
    fi
else
    echo -e "${BLUE}Data kept in /var/lib/cyrenus${NC}"
fi

# Step 6: Remove Tetragon policies
echo -e "\n${BLUE}Checking Tetragon policies...${NC}"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

if command_exists tetra; then
    echo -e "${GREEN}✓ Tetragon CLI detected${NC}"
    read -p "Remove Cyrenus Tetragon policies? (y/n) [n]: " REMOVE_POLICIES
    REMOVE_POLICIES=${REMOVE_POLICIES:-n}
    
    if [[ "$REMOVE_POLICIES" =~ ^[Yy] ]]; then
        echo "Listing applied policies..."
        
        # Try to remove known Cyrenus policies
        POLICY_NAMES=(
            "process-monitoring"
            "network-monitoring"
            "file-monitoring"
            "syscall-monitoring"
        )
        
        for policy_name in "${POLICY_NAMES[@]}"; do
            if tetra tracingpolicy list 2>/dev/null | grep -q "$policy_name"; then
                echo "Removing policy: $policy_name"
                tetra tracingpolicy delete "$policy_name" 2>/dev/null || \
                echo -e "${YELLOW}⚠ Failed to remove $policy_name${NC}"
            fi
        done
        
        echo -e "${GREEN}✓ Policies removed${NC}"
    else
        echo -e "${BLUE}Tetragon policies kept${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Tetragon CLI not found, skipping policy removal${NC}"
fi

# Step 7: Clean up build artifacts (if in source directory)
if [ -f "Makefile" ]; then
    echo -e "\n${BLUE}Cleaning build artifacts...${NC}"
    read -p "Clean build directory? (y/n) [y]: " CLEAN_BUILD
    CLEAN_BUILD=${CLEAN_BUILD:-y}
    
    if [[ "$CLEAN_BUILD" =~ ^[Yy] ]]; then
        make clean 2>/dev/null || true
        echo -e "${GREEN}✓ Build artifacts cleaned${NC}"
    fi
fi

# Final message
echo -e "\n${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Cyrenus Uninstallation Completed!          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}\n"

echo -e "${BLUE}Summary:${NC}"
echo -e "  ✓ Service stopped and disabled"
echo -e "  ✓ Binaries removed"
if [[ "$REMOVE_CONFIG" =~ ^[Yy] ]]; then
    echo -e "  ✓ Configuration removed"
else
    echo -e "  - Configuration preserved in /etc/cyrenus"
fi
if [[ "$REMOVE_DATA" =~ ^[Yy] ]]; then
    echo -e "  ✓ Data directory removed"
else
    echo -e "  - Data preserved in /var/lib/cyrenus"
fi

echo -e "\n${YELLOW}Note: System dependencies were not removed.${NC}"
echo -e "${YELLOW}If you want to remove them, please do so manually.${NC}\n"
