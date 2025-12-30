# Stage 1: Builder
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-multilib \
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
    libhpdf-dev \
    libmaxminddb-dev \
    libhpdf-dev \
    uuid-dev \
    pkg-config \
    git \
    curl \
    xxd \
    ca-certificates

# Install Node.js (Latest LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

WORKDIR /app

# Copy source code
COPY . .

# Build Web UI
RUN cd web && \
    npm install && \
    npm run build && \
    ./build.sh || true

# Build Cyrenus
RUN make clean && make all

# Stage 2: Runtime
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    libbpf0 \
    libmicrohttpd12 \
    libconfig9 \
    libjson-c5 \
    libcurl4 \
    libwebsockets16 \
    libssl3 \
    libsqlcipher0 \
    libmaxminddb0 \
    libhpdf-2.3.0 \
    uuid-runtime \
    iproute2 \
    iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /etc/cyrenus /var/lib/cyrenus /etc/tetragon/policies

# Copy binaries and config
COPY --from=builder /app/build/cyrenus /usr/local/bin/cyrenus
COPY --from=builder /app/build/xdp_prog.o /usr/local/lib/cyrenus_xdp_prog.o
COPY --from=builder /app/config/cyrenus.conf /etc/cyrenus/cyrenus.conf

# Copy policies
COPY config/tetragon/policies /etc/tetragon/policies

# Expose ports
EXPOSE 8181

# Default command
CMD ["/usr/local/bin/cyrenus", "/etc/cyrenus/cyrenus.conf"]
