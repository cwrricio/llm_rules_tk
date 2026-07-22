"""Generate the two tiny PCAPs used by the self-contained teste mínimo.

Pure standard-library (no scapy). Each PCAP holds a handful of Ethernet/IPv4/UDP
datagrams:

- ``attack.pcap`` — payload carries the signature the deployed rule looks for
  (``RULESFARMERTEST``), standing in for a detected attack.
- ``benign.pcap`` — same shape, innocuous payload; must NOT match the rule.

Replaying these through Snort in read-file mode (``snort -r``) reproduces the
detection outcome deterministically on any machine, with no live packet capture
(so no NET_RAW/NET_ADMIN capabilities, no sniffing interface, no root).
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path


# Signature the deployed Snort rule matches on. Keep in sync with SIGNATURE in
# run_teste_minimo.py.
SIGNATURE = b"RULESFARMERTEST"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    ip_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH", 0x45, 0, ip_len, 0x1234, 0, 64, 17, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return eth + ip + udp


def _write_pcap(path: Path, packets: list[bytes]) -> None:
    with path.open("wb") as f:
        # Global header: magic, version 2.4, DLT_EN10MB (1), big-endian.
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for pkt in packets:
            f.write(struct.pack("!IIII", 0, 0, len(pkt), len(pkt)) + pkt)


def generate(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    attack = out_dir / "attack.pcap"
    benign = out_dir / "benign.pcap"
    _write_pcap(
        attack,
        [_udp_packet("10.0.0.9", "10.0.0.2", 40000, 9999, b"HELLO_" + SIGNATURE + b"_FLOOD")] * 3,
    )
    _write_pcap(
        benign,
        [_udp_packet("10.0.0.9", "10.0.0.2", 40000, 9999, b"routine keepalive, nothing to see")] * 3,
    )
    return attack, benign


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("pcaps")
    a, b = generate(target)
    print(f"wrote {a} and {b}")
