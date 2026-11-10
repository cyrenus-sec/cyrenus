#!/bin/bash
# Cyrenus Live XDP + Host Security + Control-Plane Benchmark Harness (0-100 Score)
# Creates an isolated veth network namespace (cy_ns <-> veth_cy_host), launches a sandboxed
# Cyrenus instance, runs tests/benchmark_runner.py across all dual-stack L3/L4, Tetragon,
# HTTP/WS hardening, and latency checks, then cleans up every interface/netns/temp file.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "ERROR: tests/security_benchmark.sh must be run as root (requires ip netns + XDP/BPF capabilities)."
    exit 1
fi

for cmd in ip python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Missing required command '$cmd'"
        exit 1
    fi
done

if [ ! -x "./build/cyrenus" ] || [ ! -f "./build/xdp_prog.o" ]; then
    echo "Building Cyrenus binary and eBPF XDP program..."
    make all
fi

WORK_DIR="$(mktemp -d /tmp/cyrenus_bench.XXXXXX)"
NETNS="cy_ns_$$"
VETH_HOST="veth_cy_h$$"
VETH_ATT="veth_cy_a$$"
CYRENUS_PID=""

REPORT_JSON="${CYRENUS_BENCH_JSON:-${WORK_DIR}/report.json}"
REPORT_MD="${CYRENUS_BENCH_MD:-${WORK_DIR}/report.md}"
MIN_SCORE="${CYRENUS_BENCH_MIN_SCORE:-90}"

cleanup() {
    local rc=$?
    set +e
    if [ -n "$CYRENUS_PID" ] && kill -0 "$CYRENUS_PID" 2>/dev/null; then
        kill -TERM "$CYRENUS_PID" 2>/dev/null || true
        wait "$CYRENUS_PID" 2>/dev/null || true
    fi
    ip link del "$VETH_HOST" 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Ensure binary looks up local build/xdp_prog.o cleanly unless installed globally
mkdir -p "${WORK_DIR}/policies_src" "${WORK_DIR}/policies_deployed"
cp -f config/tetragon/policies/*.yaml "${WORK_DIR}/policies_src/" 2>/dev/null || true
: > "${WORK_DIR}/tetragon.log"
cat > "${WORK_DIR}/tetragon.yaml" << 'EOF'
enable-process-cred: true
enable-process-ns: true
EOF

# Generate test key & sandboxed config
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "${WORK_DIR}/master.key"
chmod 600 "${WORK_DIR}/master.key"

cat > "${WORK_DIR}/cyrenus.conf" << EOF
interface = "${VETH_HOST}";
http_port = 18181;
bind_address = "127.0.0.1";
trusted_proxy = "10.200.0.99";
cors_origin = "";
backend = {
    url = "http://127.0.0.1";
    api_key = "";
    api_secret = "";
};
username = "benchadmin";
password = "CyrenusBench#2026";
app_secret = "bench_secret_0123456789abcdef0123456789abcdef";
database = {
    path = "${WORK_DIR}/cyrenus.db";
    encrypted = true;
};
geoip = {
    database_path = "${WORK_DIR}/none.mmdb";
    auto_update = false;
};
EOF

echo "=== Setting up isolated veth network namespace (${NETNS}) ==="
ip netns add "$NETNS"
ip link add "$VETH_HOST" type veth peer name "$VETH_ATT" netns "$NETNS"

ip link set "$VETH_HOST" up
ip addr add 10.200.0.1/24 dev "$VETH_HOST"
ip addr add fd00:200::1/64 dev "$VETH_HOST" nodad
ip link add link "$VETH_HOST" name "${VETH_HOST}.100" type vlan id 100
ip addr add 10.201.0.1/24 dev "${VETH_HOST}.100"
ip link set "${VETH_HOST}.100" up

ip -n "$NETNS" link set lo up
ip -n "$NETNS" link set "$VETH_ATT" up
ip -n "$NETNS" addr add 10.200.0.2/24 dev "$VETH_ATT"
ip -n "$NETNS" addr add fd00:200::2/64 dev "$VETH_ATT" nodad
ip -n "$NETNS" link add link "$VETH_ATT" name "${VETH_ATT}.100" type vlan id 100
ip -n "$NETNS" addr add 10.201.0.2/24 dev "${VETH_ATT}.100"
ip -n "$NETNS" link set "${VETH_ATT}.100" up

MAC_HOST="$(cat "/sys/class/net/${VETH_HOST}/address")"
MAC_ATT="$(ip -n "$NETNS" link show "$VETH_ATT" | awk '/link\/ether/ {print $2}')"

# Brief settle so initial kernel RS/NS traffic finishes before clean baseline check
sleep 1.5

echo "=== Starting Cyrenus on ${VETH_HOST} (MAC ${MAC_HOST}) ==="
export CYRENUS_TETRAGON_DIR="${WORK_DIR}/policies_deployed"
export CYRENUS_POLICY_DIR="${WORK_DIR}/policies_src"
export CYRENUS_TETRAGON_CONFIG="${WORK_DIR}/tetragon.yaml"
export CYRENUS_TETRAGON_LOG="${WORK_DIR}/tetragon.log"

./build/cyrenus \
    -c "${WORK_DIR}/cyrenus.conf" \
    -d "${WORK_DIR}/cyrenus.db" \
    -k "${WORK_DIR}/master.key" \
    --no-geoip --no-notifications \
    > "${WORK_DIR}/cyrenus.log" 2>&1 &
CYRENUS_PID=$!

# Wait for HTTP API health
HEALTH_OK=0
for _ in $(seq 1 30); do
    if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18181/api/v1/system/health', timeout=1).read()" >/dev/null 2>&1; then
        HEALTH_OK=1
        break
    fi
    if ! kill -0 "$CYRENUS_PID" 2>/dev/null; then
        echo "ERROR: Cyrenus exited unexpectedly during startup! Log:"
        cat "${WORK_DIR}/cyrenus.log"
        exit 1
    fi
    sleep 0.25
done

if [ "$HEALTH_OK" -ne 1 ]; then
    echo "ERROR: Timed out waiting for Cyrenus health endpoint. Log:"
    cat "${WORK_DIR}/cyrenus.log"
    exit 1
fi

set +e
python3 tests/benchmark_runner.py \
    --url "http://127.0.0.1:18181" \
    --ws-port 18182 \
    --username "benchadmin" \
    --password "CyrenusBench#2026" \
    --netns "$NETNS" \
    --att-iface "$VETH_ATT" \
    --host-ip "10.200.0.1" \
    --host-ipv6 "fd00:200::1" \
    --host-vlan-ip "10.201.0.1" \
    --mac-host "$MAC_HOST" \
    --mac-att "$MAC_ATT" \
    --policy-dir "${WORK_DIR}/policies_src" \
    --deployed-dir "${WORK_DIR}/policies_deployed" \
    --tetragon-config "${WORK_DIR}/tetragon.yaml" \
    --tetragon-log "${WORK_DIR}/tetragon.log" \
    --report-json "$REPORT_JSON" \
    --report-md "$REPORT_MD" \
    --min-score "$MIN_SCORE"
BENCH_RC=$?
set -e

if [ -n "${CYRENUS_BENCH_COPY_MD:-}" ] && [ -f "$REPORT_MD" ]; then
    cp -f "$REPORT_MD" "$CYRENUS_BENCH_COPY_MD"
fi
if [ -n "${CYRENUS_BENCH_COPY_JSON:-}" ] && [ -f "$REPORT_JSON" ]; then
    cp -f "$REPORT_JSON" "$CYRENUS_BENCH_COPY_JSON"
fi

if [ "$BENCH_RC" -ne 0 ]; then
    echo "=== Cyrenus Daemon Log (tail 60) ==="
    tail -n 60 "${WORK_DIR}/cyrenus.log" || true
fi

exit "$BENCH_RC"

