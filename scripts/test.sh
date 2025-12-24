#!/bin/bash

# Set the base URL for your API
BASE_URL="http://localhost:8181"  # Adjust this to your server's address and port

# 1. Login to get a token
echo "Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/login" \
     -d "username=admin&password=secret")
TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.token')

if [ -z "$TOKEN" ]; then
    echo "Login failed. Response: $LOGIN_RESPONSE"
    exit 1
fi

echo "Logged in successfully. Token: $TOKEN"

# Function to make authenticated requests
auth_curl() {
    curl -s -H "Authorization: Bearer $TOKEN" "$@"
}

# 2. Get traffic data
echo -e "\nGetting traffic data..."
auth_curl "${BASE_URL}/api/traffic" | jq .

# 3. Get rules
echo -e "\nGetting rules..."
auth_curl "${BASE_URL}/api/rules" | jq .

# 4. Add a new rule
echo -e "\nAdding a new rule..."
NEW_RULE='{
    "ip": "192.168.1.100",
    "port": 8080,
    "action": "block"
}'
auth_curl -X POST "${BASE_URL}/api/rules" \
     -H "Content-Type: application/json" \
     -d "$NEW_RULE"

# Get rules again to confirm addition
echo -e "\nGetting rules after addition..."
auth_curl "${BASE_URL}/api/rules" | jq .

# 5. Delete a rule
echo -e "\nDeleting the newly added rule..."
RULE_ID="192.168.1.100_8080_0"  # Adjust this based on your rule identification method
auth_curl -X DELETE "${BASE_URL}/api/rules/${RULE_ID}"

# Get rules one last time to confirm deletion
echo -e "\nGetting rules after deletion..."
auth_curl "${BASE_URL}/api/rules" | jq .

echo -e "\nAPI testing completed."
