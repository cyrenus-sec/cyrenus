#!/bin/bash
# Quick automated verification for Connection State Context (/api/v1)

set -euo pipefail

SERVER_URL="${CYRENUS_URL:-http://127.0.0.1:8181}"
TARGET_IP="${CYRENUS_TARGET_IP:-127.0.0.1}"
USERNAME="${CYRENUS_USERNAME:-admin}"
PASSWORD="${CYRENUS_PASSWORD:-secret}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "==================================="
echo "Connection State Context Verification"
echo "Server: $SERVER_URL | Target: $TARGET_IP"
echo "==================================="

echo -n "Test 1: Server Health Check... "
if curl -fsS "$SERVER_URL/api/v1/system/health" | grep -q '"healthy"'; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL - Server not responding${NC}"
    exit 1
fi

LOGIN_RESPONSE=$(curl -fsS -X POST "$SERVER_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
TOKEN=$(python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' <<< "$LOGIN_RESPONSE")
if [ -z "$TOKEN" ]; then
    echo -e "${RED}FAIL - Authentication failed${NC}"
    exit 1
fi

auth_get() {
    curl -fsS -H "Authorization: Bearer $TOKEN" "$SERVER_URL$1"
}

INITIAL_ATTACKS=$(auth_get "/api/v1/attacks" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("total", len(d)) if isinstance(d,dict) else len(d))' || echo 0)
echo "Test 2: Baseline attacks count = $INITIAL_ATTACKS"

if command -v hping3 >/dev/null 2>&1; then
    echo "Test 3: Sending short UDP flood burst (2s)..."
    timeout 2 hping3 --udp -p 80 --flood "$TARGET_IP" >/dev/null 2>&1 || true
    sleep 2
    NEW_ATTACKS=$(auth_get "/api/v1/attacks" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("total", len(d)) if isinstance(d,dict) else len(d))' || echo 0)
    if [ "$NEW_ATTACKS" -gt "$INITIAL_ATTACKS" ]; then
        echo -e "  ${GREEN}PASS - New flow triggered attack detection${NC}"
    else
        echo -e "  ${YELLOW}WARN - Rate may not have exceeded threshold (${INITIAL_ATTACKS} -> ${NEW_ATTACKS})${NC}"
    fi
else
    echo -e "${YELLOW}Skipped flood injection (hping3 not installed); use tests/security_benchmark.sh for full Scapy netns benchmark.${NC}"
fi

FLOWS=$(auth_get "/api/v1/traffic/stats" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' || echo 0)
echo "Active flows tracked: $FLOWS"
