# Compiler for user-space programs
CC = gcc
CFLAGS = -I./include -I/usr/include/bpf -I/usr/include/json-c -Wall -Werror
# Compiler for eBPF programs
CLANG = clang
BPF_CFLAGS = -target bpf -I./include -I/usr/include/bpf -Wall -O2 -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -g


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