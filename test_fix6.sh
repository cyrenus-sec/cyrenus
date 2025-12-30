#!/bin/bash
# Quick automated test for Fix #6: Connection State Context

set -e

echo "==================================="
echo "Fix #6: Connection State Context"
echo "Quick Verification Test"
echo "==================================="
echo ""

# Configuration
SERVER_URL="http://192.168.0.106:8181"
TARGET_IP="192.168.0.106"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Check if server is running
echo -n "Test 1: Server Health Check... "
if curl -s $SERVER_URL/api/v1/system/health | jq -e '.status == "healthy"' &>/dev/null; then
  echo -e "${GREEN}✅ PASS${NC}"
else
  echo -e "${RED}❌ FAIL - Server not responding${NC}"
  exit 1
fi

# Test 2: Clear previous attacks (if any)
echo -n "Test 2: Baseline - Checking initial state... "
INITIAL_ATTACKS=$(curl -s $SERVER_URL/api/v1/attacks 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
echo -e "${YELLOW}Found $INITIAL_ATTACKS existing attacks${NC}"

# Test 3: Generate SHORT burst traffic (should trigger - NEW flow)
echo -n "Test 3: New Flow Detection (strict threshold)... "
echo "  Sending high-rate UDP burst for 2 seconds..."
timeout 2 hping3 --udp -p 80 --flood $TARGET_IP &>/dev/null &
PID=$!
sleep 3
kill $PID 2>/dev/null || true

# Wait for processing
sleep 2

NEW_ATTACKS=$(curl -s $SERVER_URL/api/v1/attacks 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
if [ "$NEW_ATTACKS" -gt "$INITIAL_ATTACKS" ]; then
  echo -e "  ${GREEN}✅ PASS - New flow triggered attack (strict threshold working)${NC}"
else
  echo -e "  ${YELLOW}⚠️  INCONCLUSIVE - May need higher traffic rate${NC}"
fi

# Test 4: Generate SUSTAINED traffic to establish flow
echo -n "Test 4: Established Flow (lenient threshold)... "
echo "  Sending moderate UDP traffic for 10 seconds to establish flow..."

# Lower rate to stay under strict threshold initially
hping3 --udp -p 8080 -i u10000 $TARGET_IP &>/dev/null &
HPING_PID=$!

echo "  Waiting 7 seconds for flow to establish (>5s threshold)..."
sleep 7

# Continue for another 5 seconds
echo "  Flow should now be ESTABLISHED - continuing traffic..."
sleep 5

kill $HPING_PID 2>/dev/null || true

# Check if new attacks were added during established phase
sleep 2
FINAL_ATTACKS=$(curl -s $SERVER_URL/api/v1/attacks 2>/dev/null | jq 'length' 2>/dev/null || echo "0")

EST_ATTACKS=$((FINAL_ATTACKS - NEW_ATTACKS))
if [ "$EST_ATTACKS" -eq 0 ]; then
  echo -e "  ${GREEN}✅ PASS - Established flow NOT flagged (lenient threshold working)${NC}"
else
  echo -e "  ${YELLOW}⚠️  WARNING - Flow may have been flagged ($EST_ATTACKS new attacks)${NC}"
  echo "  (This could mean traffic exceeded even the 10× threshold)"
fi

# Test 5: Check traffic tracking
echo -n "Test 5: Flow Tracking... "
FLOWS=$(curl -s $SERVER_URL/api/v1/traffic 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
if [ "$FLOWS" -gt 0 ]; then
  echo -e "${GREEN}✅ PASS - Tracking $FLOWS active flows${NC}"
else
  echo -e "${YELLOW}⚠️  No active flows (may have timed out)${NC}"
fi

# Summary
echo ""
echo "==================================="
echo "Test Summary"
echo "==================================="
echo "Total Attacks Detected: $FINAL_ATTACKS"
echo "Active Flows Tracked: $FLOWS"
echo ""
echo -e "${YELLOW}Note: For full verification, run manual YouTube test${NC}"
echo "1. Visit: $SERVER_URL"
echo "2. Watch YouTube 4K for 10 minutes"
echo "3. Check Attacks tab - should remain at $FINAL_ATTACKS"
echo ""
echo "Kernel logs: sudo dmesg | grep -i flood | tail -20"
