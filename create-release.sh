#!/bin/bash
# Manual release creation script
# Use this if 'make release' fails due to memory issues

set -e

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")}"
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64) RELEASE_ARCH="amd64" ;;
    aarch64|arm64) RELEASE_ARCH="arm64" ;;
    *) RELEASE_ARCH="$ARCH_RAW" ;;
esac
RELEASE_NAME="cyrenus-${VERSION}-linux-${RELEASE_ARCH}"

echo "Creating release: $RELEASE_NAME"

if [ ! -x build/cyrenus ] || [ ! -f build/xdp_prog.o ]; then
    echo "ERROR: build/cyrenus or build/xdp_prog.o missing. Run 'make' first." >&2
    exit 1
fi

# Create releases directory
mkdir -p releases

# Create tarball with directory wrapper matching 'make release' and install-binary.sh
echo "Creating tarball..."
tar -czf "releases/${RELEASE_NAME}.tar.gz" \
    --transform="s,^build/,${RELEASE_NAME}/," \
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
