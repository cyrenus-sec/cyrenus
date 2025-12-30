#!/bin/bash
# Manual release creation script
# Use this if 'make release' fails due to memory issues

set -e

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")
RELEASE_NAME="cyrenus-${VERSION}-linux-amd64"

echo "Creating release: $RELEASE_NAME"

# Create releases directory
mkdir -p releases

# Create tarball directly without intermediate directory
echo "Creating tarball..."
tar -czf "releases/${RELEASE_NAME}.tar.gz" \
    --transform="s,^build/cyrenus,cyrenus," \
    --transform="s,^build/xdp_prog.o,xdp_prog.o," \
    build/cyrenus \
    build/xdp_prog.o

# Generate checksum
cd releases
sha256sum "${RELEASE_NAME}.tar.gz" > "${RELEASE_NAME}.tar.gz.sha256"
cd ..

echo "✓ Release created: releases/${RELEASE_NAME}.tar.gz"
echo "✓ SHA256: $(cat releases/${RELEASE_NAME}.tar.gz.sha256)"
echo ""
echo "Upload this file to GitHub releases:"
echo "  releases/${RELEASE_NAME}.tar.gz"
