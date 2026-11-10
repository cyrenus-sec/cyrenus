# Stage 1: Builder
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    uuid-dev \
    zlib1g-dev \
    pkg-config \
    git \
    curl \
    xxd \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (20 LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Ensure scripts use Unix LF line endings and executable permissions
RUN find . -name "*.sh" -exec sed -i 's/\r$//' {} + && \
    chmod +x web/build.sh

# Build frontend assets, eBPF program, and Cyrenus binary
RUN make clean && make all

# Stage 2: Runtime
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies (Ubuntu 24.04 Noble t64/SONAME packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1t64 \
    libbpf1 \
    libmicrohttpd12t64 \
    libconfig9 \
    libjson-c5 \
    libcurl4t64 \
    libwebsockets19t64 \
    libssl3t64 \
    libsqlcipher1 \
    libmaxminddb0 \
    libuuid1 \
    uuid-runtime \
    zlib1g \
    iproute2 \
    iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /etc/cyrenus /var/lib/cyrenus /etc/tetragon/policies /var/log/tetragon

# Copy binaries and config
COPY --from=builder /app/build/cyrenus /usr/local/bin/cyrenus
COPY --from=builder /app/build/xdp_prog.o /usr/local/lib/cyrenus_xdp_prog.o
COPY --from=builder /app/config/cyrenus.conf /etc/cyrenus/cyrenus.conf

# Copy policies
COPY config/tetragon/policies /etc/tetragon/policies

# Expose ports (HTTP API/UI + WebSocket)
EXPOSE 8181 8182

# Default command
CMD ["/usr/local/bin/cyrenus", "/etc/cyrenus/cyrenus.conf"]
