#!/bin/bash
set -e

# Default to current directory if not specified
WEB_DIR="$(dirname "$0")"
cd "$WEB_DIR"

echo "=== Building Cyrenus Frontend ==="

# Check for npm
if ! command -v npm &> /dev/null; then
    echo "ERROR: npm not found. Please install Node.js and npm."
    exit 1
fi

# Check for xxd
if ! command -v xxd &> /dev/null; then
    echo "ERROR: xxd not found. Please install xxd (usually part of vim-common or xxd package)."
    exit 1
fi

# Install dependencies if node_modules missing
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Build
echo "Bundling assets..."
cp src/index.html dist/
cp src/login.html dist/
npm run build

# Ensure include directory exists
mkdir -p ../include

# Convert to C headers
echo "Embedding assets into C headers..."
cd dist
xxd -i index.html > ../../include/web_index.h
xxd -i login.html > ../../include/web_login.h
xxd -i app.js > ../../include/web_app.h
xxd -i styles.css > ../../include/web_styles.h
cd ..

echo "Frontend build complete."
echo "Generated: include/web_index.h, include/web_login.h, include/web_app.h, include/web_styles.h"
