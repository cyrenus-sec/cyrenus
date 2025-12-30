#!/bin/bash
# Verify Cyrenus Tetragon Policies

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Verifying Active Policies ===${NC}"
# Check if policies are loaded
ACTIVE_POLICIES=$(sudo tetra tracingpolicy list 2>/dev/null)
if [[ -z "$ACTIVE_POLICIES" ]]; then
    echo -e "${RED}✗ No Tetragon policies found!${NC}"
    echo "Please run install.sh and choose to apply policies."
else
    echo -e "${GREEN}✓ Policies detected:${NC}"
    echo "$ACTIVE_POLICIES"
fi

echo -e "\n${BLUE}=== Running Policy Tests ===${NC}"

# Test 1: Anti-RCE (Block Shell Execution)
# This mimics a web server spawning a shell (uid != 0 usually, but here just testing execve block)
# The policy matches /bin/sh, /bin/bash, /bin/dash
echo -n "Test 1: Blocking shell execution (/bin/dash)... "
# Try to run dash and immediately exit. If killed, it won't run.
if sudo -u nobody /bin/dash -c "exit 0" 2>/dev/null; then
     # If it succeeded, it wasn't blocked (or policy logic allows standalone usage)
     # The policy says: execve of /bin/sh, /bin/bash, /bin/dash -> SIGKILL.
     # Wait, matchArgs index:0 Equal /bin/sh... depends on how it's called.
     echo -e "${RED}Failed (Not Blocked)${NC}"
else
    echo -e "${GREEN}Passed (Blocked/Killed)${NC}"
fi

# Test 2: Nmap execution (Policy #6)
echo -n "Test 2: Logging Nmap usage... "
if command -v nmap >/dev/null; then
    nmap --version >/dev/null 2>&1
    echo -e "${GREEN}Executed (Check logs)${NC}"
else
    echo -e "${YELLOW}Skipped (nmap not installed)${NC}"
fi

# Test 3: Suspicious Listen (Policy #7)
echo -n "Test 3: Suspicious Listener (nc -l 1337)... "
timeout 2s nc -l -p 1337 >/dev/null 2>&1 &
PID=$!
sleep 1
if ps -p $PID >/dev/null; then
    kill $PID 2>/dev/null
    echo -e "${GREEN}Executed (Check logs)${NC}"
else
    echo -e "${GREEN}Passed (Process Killed/Terminated)${NC}"
fi

echo -e "\n${BLUE}=== Verification Complete ===${NC}"
echo "Check /var/log/tetragon/tetragon.log or 'tetra getevents' for details."
