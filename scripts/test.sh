#!/bin/bash
set -euo pipefail

# Set the base URL and credentials via environment variables if non-default
BASE_URL="${CYRENUS_URL:-http://127.0.0.1:8181}"
USERNAME="${CYRENUS_USERNAME:-admin}"
PASSWORD="${CYRENUS_PASSWORD:-secret}"

echo "=== Cyrenus API Smoke Test (${BASE_URL}) ==="

echo "1. Checking /api/v1/system/health..."
curl -fsS "${BASE_URL}/api/v1/system/health"
echo ""

echo "2. Authenticating via POST /api/v1/auth/login..."
LOGIN_PAYLOAD=$(printf '{"username":"%s","password":"%s"}' "$USERNAME" "$PASSWORD")
LOGIN_RESPONSE=$(curl -fsS -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "$LOGIN_PAYLOAD")

if command -v jq >/dev/null 2>&1; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')
else
    TOKEN=$(python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' <<< "$LOGIN_RESPONSE")
fi

if [ -z "$TOKEN" ]; then
    echo "Login failed. Response: $LOGIN_RESPONSE"
    exit 1
fi
echo "Logged in successfully."

auth_curl() {
    curl -fsS -H "Authorization: Bearer $TOKEN" "$@"
}

echo "3. Fetching live traffic telemetry..."
auth_curl "${BASE_URL}/api/v1/traffic/stats" | head -c 500
echo ""

echo "4. Fetching firewall rules..."
auth_curl "${BASE_URL}/api/v1/rules"
echo ""

echo "5. Deploying temporary DROP rule for 192.0.2.100..."
NEW_RULE='{
    "ip": "192.0.2.100",
    "port": 8080,
    "proto": "tcp",
    "action": "drop",
    "description": "Smoke test rule"
}'
auth_curl -X POST "${BASE_URL}/api/v1/rules" \
    -H "Content-Type: application/json" \
    -d "$NEW_RULE"
echo ""

echo "6. Verifying rule presence..."
auth_curl "${BASE_URL}/api/v1/rules" | grep -q "192.0.2.100"

echo "7. Deleting temporary rule..."
RULE_ID="192.0.2.100_8080_6"
auth_curl -X DELETE "${BASE_URL}/api/v1/rules/${RULE_ID}"
echo ""

echo "API smoke testing completed successfully."
