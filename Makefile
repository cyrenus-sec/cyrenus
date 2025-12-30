# Compiler for user-space programs
CC = gcc
CFLAGS = -I./include -I/usr/include/bpf -I/usr/include/json-c -Wall -Werror
# Detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
    RELEASE_ARCH := amd64
else ifneq ($(filter aarch64 arm64,$(ARCH)),)
    BPF_ARCH := arm64
    RELEASE_ARCH := arm64
else
    BPF_ARCH := $(ARCH)
    RELEASE_ARCH := $(ARCH)
endif

# Compiler for eBPF programs
CLANG = clang
BPF_CFLAGS = -target bpf -I./include -I/usr/include/bpf -Wall -O2 -D__TARGET_ARCH_$(BPF_ARCH) -I/usr/include/$(shell uname -m)-linux-gnu -g

# Linker flags for user-space programs
LDFLAGS = -lbpf -lelf -lz -lcurl -lpthread -lmicrohttpd -lconfig -ljson-c -luuid -lcrypto -lwebsockets -lsqlcipher -lmaxminddb

# Source files
KERNEL_SRC = ebpf/xdp_prog.c
USER_SRC = src/main.c src/http_server.c src/config_handler.c src/bpf_loader.c src/attack_info.c src/runtime_config.c src/database.c src/geoip.c src/websocket_server.c src/tetragon_events.c \
           src/api/auth.c src/api/system.c src/api/attacks.c src/api/traffic.c src/api/rules.c src/api/iplists.c src/api/geoip.c src/api/security.c src/api/api_helpers.c src/saas_uplink.c src/api/keys.c

# Output files
KERNEL_OBJ = build/xdp_prog.o
USER_OBJ = build/cyrenus

# Targets
.PHONY: all clean test frontend

all: frontend $(KERNEL_OBJ) $(USER_OBJ)

frontend:
	./web/build.sh

$(KERNEL_OBJ): $(KERNEL_SRC)
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_OBJ): $(USER_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf build
	
# For development: add a target to compile and check eBPF program
check_ebpf: $(KERNEL_OBJ)
	llvm-objdump -S $(KERNEL_OBJ)

# Add a target to install the program
install: $(KERNEL_OBJ) $(USER_OBJ)
	install -m 755 $(USER_OBJ) /usr/local/bin/cyrenus
	install -m 644 $(KERNEL_OBJ) /usr/local/lib/cyrenus_xdp_prog.o

# Add a target to uninstall the program
uninstall:
	rm -f /usr/local/bin/cyrenus /usr/local/lib/cyrenus_xdp_prog.o

# Create release tarball for distribution
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")
RELEASE_NAME = cyrenus-$(VERSION)-linux-$(RELEASE_ARCH)

release: $(KERNEL_OBJ) $(USER_OBJ)
	@echo "Creating release package: $(RELEASE_NAME)"
	@mkdir -p releases/$(RELEASE_NAME)
	@cp $(USER_OBJ) releases/$(RELEASE_NAME)/cyrenus
	@cp $(KERNEL_OBJ) releases/$(RELEASE_NAME)/xdp_prog.o
	@cd releases && tar -czf $(RELEASE_NAME).tar.gz $(RELEASE_NAME)/
	@cd releases && sha256sum $(RELEASE_NAME).tar.gz > $(RELEASE_NAME).tar.gz.sha256
	@rm -rf releases/$(RELEASE_NAME)
	@echo "Release package created: releases/$(RELEASE_NAME).tar.gz"
	@echo "SHA256: $$(cat releases/$(RELEASE_NAME).tar.gz.sha256)"