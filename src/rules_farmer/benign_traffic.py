"""Generators for real benign protocol traffic.

Each generator produces legitimate, non-attack traffic targeting the testbed servers.
They are executed via SSH on Entity 3 (attacker host) targeting Entity 2 (victim host)
so that the Snort IDS on Entity 2 sees the traffic and can be tested for false positives.

Each protocol is exercised through SEVERAL legitimate profiles (different operation,
payload size and client cadence), not a single fixed pattern. "Passing the benign check"
then means the rule stayed silent across a spread of realistic traffic, not just one
sample — which is what makes the false-positive guarantee worth stating. A rule that
fires on ANY profile is a false positive: the alert log accumulates across profiles, so
the single post-run check in run_benign_traffic catches all of them.

Usage (from orchestrator or CLI):

    gen = BenignTrafficRunner(ssh_client=attacker_ssh)
    result = gen.run(protocol="xrce", target_ip="192.168.137.1", duration_seconds=30)
    assert result.ok

Required servers on Entity 2 (192.168.137.1) — see docs/benign_traffic_setup.md.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass
from typing import Literal

from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


Protocol = Literal["xrce", "mqtt", "http"]


@dataclass(frozen=True)
class BenignRunResult:
    protocol: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class BenignProfile:
    """One legitimate traffic pattern for a protocol.

    ``args`` are extra positional arguments appended to the protocol script after
    ``target_ip target_port duration`` — they select the operation, payload size and
    cadence so each profile stresses a different, still-legitimate corner of the protocol.
    """

    name: str
    args: tuple[str, ...]


# ---------------------------------------------------------------------------
# Inline Python scripts executed on the attacker host via SSH.
# Each script uses only the standard library so no extra packages are needed.
# Every script is parametrized so one script drives all profiles of its protocol.
# ---------------------------------------------------------------------------

# argv: TARGET_IP TARGET_PORT DURATION [SUBMSG_ID_HEX] [PAD_BYTES] [MIN_GAP] [MAX_GAP]
_XRCE_BENIGN_SCRIPT = """\
import socket, time, struct, random, sys

TARGET_IP   = sys.argv[1]
TARGET_PORT = int(sys.argv[2])
DURATION    = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0
SUBMSG_ID   = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x0B
PAD         = int(sys.argv[5]) if len(sys.argv) > 5 else 0
MIN_GAP     = float(sys.argv[6]) if len(sys.argv) > 6 else 0.5
MAX_GAP     = float(sys.argv[7]) if len(sys.argv) > 7 else 2.0

def make_xrce(submsg_id, pad, seq=0):
    # Minimal XRCE-DDS submessage: 4-byte session header + one submessage.
    header = struct.pack('<BBHB', 0x00, 0x00, seq & 0xFFFF, 0x00)
    body   = struct.pack('<II', 0, seq) + bytes(pad)
    submsg = struct.pack('<BBH', submsg_id, 0x07, len(body)) + body
    return header + submsg

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
end = time.time() + DURATION
seq = 0
sent = 0
print(f"XRCE-DDS benign submsg=0x{SUBMSG_ID:02x} pad={PAD} to {TARGET_IP}:{TARGET_PORT} for {DURATION}s")
while time.time() < end:
    sock.sendto(make_xrce(SUBMSG_ID, PAD, seq), (TARGET_IP, TARGET_PORT))
    sent += 1
    seq += 1
    time.sleep(random.uniform(MIN_GAP, MAX_GAP))  # normal client cadence
sock.close()
print(f"Sent {sent} benign XRCE-DDS submessages")
"""

# argv: TARGET_IP TARGET_PORT DURATION [MODE] [MIN_GAP] [MAX_GAP]
_MQTT_BENIGN_SCRIPT = """\
import socket, time, struct, sys, random

TARGET_IP   = sys.argv[1]
TARGET_PORT = int(sys.argv[2])
DURATION    = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0
MODE        = sys.argv[4] if len(sys.argv) > 4 else "publish"
MIN_GAP     = float(sys.argv[5]) if len(sys.argv) > 5 else 2.0
MAX_GAP     = float(sys.argv[6]) if len(sys.argv) > 6 else 5.0
CLIENT_ID   = b"benign_client_" + str(random.randint(1000, 9999)).encode()
TOPIC       = b"test/benign"
PAYLOAD     = b"hello"

def encode_remaining(n):
    out = b""
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out += bytes([byte])
        if n == 0:
            break
    return out

def mqtt_connect(client_id):
    proto_name = b"\\x00\\x04MQTT"
    flags       = b"\\x02"          # clean session
    keepalive   = struct.pack(">H", 60)
    id_len      = struct.pack(">H", len(client_id))
    body        = proto_name + b"\\x04" + flags + keepalive + id_len + client_id
    return b"\\x10" + encode_remaining(len(body)) + body

def mqtt_publish(topic, payload):
    body = struct.pack(">H", len(topic)) + topic + payload
    return b"\\x30" + encode_remaining(len(body)) + body

def mqtt_subscribe(topic, pkt_id):
    body = struct.pack(">H", pkt_id) + struct.pack(">H", len(topic)) + topic + b"\\x00"
    return b"\\x82" + encode_remaining(len(body)) + body

def mqtt_pingreq():
    return b"\\xc0\\x00"

def mqtt_disconnect():
    return b"\\xe0\\x00"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5.0)
sock.connect((TARGET_IP, TARGET_PORT))
sock.sendall(mqtt_connect(CLIENT_ID))
time.sleep(0.2)
end  = time.time() + DURATION
sent = 0
print(f"MQTT benign mode={MODE} to {TARGET_IP}:{TARGET_PORT} for {DURATION}s")
while time.time() < end:
    if MODE == "subscribe":
        sock.sendall(mqtt_subscribe(TOPIC, sent + 1))
    elif MODE == "pingreq":
        sock.sendall(mqtt_pingreq())
    else:
        sock.sendall(mqtt_publish(TOPIC, PAYLOAD))
    sent += 1
    time.sleep(random.uniform(MIN_GAP, MAX_GAP))  # normal client cadence
sock.sendall(mqtt_disconnect())
sock.close()
print(f"Sent {sent} benign MQTT {MODE} messages")
"""

# argv: TARGET_IP TARGET_PORT DURATION [METHOD] [MIN_GAP] [MAX_GAP]
_HTTP_BENIGN_SCRIPT = """\
import socket, time, sys, random

TARGET_IP   = sys.argv[1]
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
DURATION    = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0
METHOD      = sys.argv[4] if len(sys.argv) > 4 else "GET"
MIN_GAP     = float(sys.argv[5]) if len(sys.argv) > 5 else 1.0
MAX_GAP     = float(sys.argv[6]) if len(sys.argv) > 6 else 3.0

PATHS = ["/", "/index.html", "/health", "/status"]

def build_request(method, path):
    if method == "POST":
        body = "field=benign&n=1"
        return (
            f"POST {path} HTTP/1.1\\r\\nHost: {TARGET_IP}\\r\\n"
            f"Content-Type: application/x-www-form-urlencoded\\r\\n"
            f"Content-Length: {len(body)}\\r\\nConnection: close\\r\\n\\r\\n{body}"
        )
    return f"{method} {path} HTTP/1.1\\r\\nHost: {TARGET_IP}\\r\\nConnection: close\\r\\n\\r\\n"

end  = time.time() + DURATION
sent = 0
print(f"HTTP benign {METHOD} to {TARGET_IP}:{TARGET_PORT} for {DURATION}s")
while time.time() < end:
    path = random.choice(PATHS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((TARGET_IP, TARGET_PORT))
        s.sendall(build_request(METHOD, path).encode())
        s.recv(4096)
        s.close()
        sent += 1
    except Exception:
        pass
    time.sleep(random.uniform(MIN_GAP, MAX_GAP))
print(f"Sent {sent} benign HTTP {METHOD} requests")
"""

_SCRIPTS: dict[Protocol, str] = {
    "xrce": _XRCE_BENIGN_SCRIPT,
    "mqtt": _MQTT_BENIGN_SCRIPT,
    "http": _HTTP_BENIGN_SCRIPT,
}

# Several legitimate profiles per protocol: different operation, payload size and cadence.
# The rule must stay silent on ALL of them to pass the benign check.
_PROFILES: dict[Protocol, tuple[BenignProfile, ...]] = {
    "xrce": (
        BenignProfile("ping", ("0x0B", "0", "0.5", "2.0")),
        BenignProfile("register", ("0x01", "32", "1.0", "3.0")),
        BenignProfile("heartbeat", ("0x07", "8", "2.0", "4.0")),
    ),
    "mqtt": (
        BenignProfile("publish", ("publish", "2.0", "5.0")),
        BenignProfile("subscribe", ("subscribe", "3.0", "6.0")),
        BenignProfile("pingreq", ("pingreq", "4.0", "8.0")),
    ),
    "http": (
        BenignProfile("get", ("GET", "1.0", "3.0")),
        BenignProfile("head", ("HEAD", "1.5", "3.5")),
        BenignProfile("post", ("POST", "2.0", "4.0")),
    ),
}

_DEFAULT_PORTS: dict[Protocol, int] = {
    "xrce": 8888,
    "mqtt": 1883,
    "http": 80,
}

# Never let a single profile run for less than this — a window too short to look
# like a real client even when many profiles share a modest total duration.
_MIN_PROFILE_SECONDS = 3.0


class BenignTrafficRunner:
    """Execute benign protocol traffic via SSH on the attacker host.

    The attacker host (Entity 3) sends legitimate traffic to Entity 2.
    Snort on Entity 2 monitors this traffic so we can measure false positives.
    Each protocol is exercised through several legitimate profiles (see ``_PROFILES``).
    """

    def __init__(self, ssh_client: SSHClient):
        self._ssh = ssh_client

    def run(
        self,
        protocol: Protocol,
        target_ip: str,
        duration_seconds: float = 20.0,
        target_port: int | None = None,
    ) -> BenignRunResult:
        port = target_port or _DEFAULT_PORTS[protocol]
        script = _SCRIPTS[protocol]
        profiles = _PROFILES[protocol]
        python_code = shlex.quote(script)
        per_profile = max(duration_seconds / len(profiles), _MIN_PROFILE_SECONDS)

        logger.info(
            "Running benign %s traffic target=%s:%s duration=%ss profiles=%s",
            protocol,
            target_ip,
            port,
            duration_seconds,
            [p.name for p in profiles],
        )

        exit_code = 0
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        for profile in profiles:
            extra = " ".join(shlex.quote(a) for a in profile.args)
            cmd = (
                f"python3 -c {python_code} "
                f"{shlex.quote(target_ip)} {port} {per_profile} {extra}"
            )
            logger.info("Benign %s profile=%s starting", protocol, profile.name)
            result = self._ssh.run_command(cmd)
            if result.exit_code != 0 and exit_code == 0:
                exit_code = result.exit_code
            stdout_parts.append(f"[{profile.name}] {(result.stdout or '').strip()}")
            if result.stderr:
                stderr_parts.append(f"[{profile.name}] {result.stderr.strip()}")

        logger.info(
            "Benign %s traffic finished exit_code=%s profiles=%s",
            protocol,
            exit_code,
            len(profiles),
        )
        return BenignRunResult(
            protocol=protocol,
            exit_code=exit_code,
            stdout="\n".join(stdout_parts),
            stderr="\n".join(stderr_parts),
        )
