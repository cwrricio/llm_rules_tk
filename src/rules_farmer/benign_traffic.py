"""Generators for real benign protocol traffic.

Each generator produces legitimate, non-attack traffic targeting the testbed servers.
They are executed via SSH on Entity 3 (attacker host) targeting Entity 2 (victim host)
so that the Snort IDS on Entity 2 sees the traffic and can be tested for false positives.

Usage (from orchestrator or CLI):

    gen = BenignTrafficRunner(ssh_client=attacker_ssh, config=config)
    result = gen.run(protocol="xrce", duration_seconds=30)
    assert not result.errors

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


# ---------------------------------------------------------------------------
# Inline Python scripts executed on the attacker host via SSH.
# Each script uses only the standard library so no extra packages are needed.
# ---------------------------------------------------------------------------

_XRCE_BENIGN_SCRIPT = """\
import socket, time, struct, random, sys

TARGET_IP = sys.argv[1]
TARGET_PORT = int(sys.argv[2])
DURATION  = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0

def make_xrce_ping(session_id=0x00, stream_id=0x00, seq=0):
    # Minimal XRCE-DDS PING submessage (ID=0x0B, flags=0x07, length=8)
    header = struct.pack('<BBHB', session_id, stream_id, seq & 0xFFFF, 0x00)
    submsg = struct.pack('<BBH', 0x0B, 0x07, 8) + struct.pack('<II', 0, seq)
    return header + submsg

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
end = time.time() + DURATION
seq = 0
sent = 0
print(f"XRCE-DDS benign ping to {TARGET_IP}:{TARGET_PORT} for {DURATION}s")
while time.time() < end:
    pkt = make_xrce_ping(seq=seq)
    sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
    sent += 1
    seq += 1
    time.sleep(random.uniform(0.5, 2.0))  # normal client cadence: 0.5-2s between pings
sock.close()
print(f"Sent {sent} benign XRCE-DDS pings")
"""

_MQTT_BENIGN_SCRIPT = """\
import socket, time, struct, sys, random

TARGET_IP   = sys.argv[1]
TARGET_PORT = int(sys.argv[2])
DURATION    = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0
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
    payload     = id_len + client_id
    body        = proto_name + b"\\x04" + flags + keepalive + payload
    return b"\\x10" + encode_remaining(len(body)) + body

def mqtt_publish(topic, payload, pkt_id=1):
    t_len   = struct.pack(">H", len(topic))
    body    = t_len + topic + payload
    return b"\\x30" + encode_remaining(len(body)) + body

def mqtt_disconnect():
    return b"\\xe0\\x00"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5.0)
sock.connect((TARGET_IP, TARGET_PORT))
sock.sendall(mqtt_connect(CLIENT_ID))
time.sleep(0.2)
end  = time.time() + DURATION
sent = 0
print(f"MQTT benign publish to {TARGET_IP}:{TARGET_PORT} topic={TOPIC.decode()} for {DURATION}s")
while time.time() < end:
    sock.sendall(mqtt_publish(TOPIC, PAYLOAD, sent + 1))
    sent += 1
    time.sleep(random.uniform(2.0, 5.0))  # normal publish cadence
sock.sendall(mqtt_disconnect())
sock.close()
print(f"Sent {sent} benign MQTT PUBLISH messages")
"""

_HTTP_BENIGN_SCRIPT = """\
import socket, time, sys, random

TARGET_IP   = sys.argv[1]
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
DURATION    = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0

PATHS = ["/", "/index.html", "/health", "/status"]

end  = time.time() + DURATION
sent = 0
print(f"HTTP benign GET to {TARGET_IP}:{TARGET_PORT} for {DURATION}s")
while time.time() < end:
    path = random.choice(PATHS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((TARGET_IP, TARGET_PORT))
        req = f"GET {path} HTTP/1.1\\r\\nHost: {TARGET_IP}\\r\\nConnection: close\\r\\n\\r\\n"
        s.sendall(req.encode())
        s.recv(4096)
        s.close()
        sent += 1
    except Exception as e:
        pass
    time.sleep(random.uniform(1.0, 3.0))
print(f"Sent {sent} benign HTTP GET requests")
"""

_SCRIPTS: dict[Protocol, str] = {
    "xrce": _XRCE_BENIGN_SCRIPT,
    "mqtt": _MQTT_BENIGN_SCRIPT,
    "http": _HTTP_BENIGN_SCRIPT,
}

_DEFAULT_PORTS: dict[Protocol, int] = {
    "xrce": 8888,
    "mqtt": 1883,
    "http": 80,
}


class BenignTrafficRunner:
    """Execute benign protocol traffic via SSH on the attacker host.

    The attacker host (Entity 3) sends legitimate traffic to Entity 2.
    Snort on Entity 2 monitors this traffic so we can measure false positives.
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
        python_code = shlex.quote(script)
        cmd = (
            f"python3 -c {python_code} "
            f"{shlex.quote(target_ip)} {port} {duration_seconds}"
        )
        logger.info(
            "Running benign %s traffic target=%s:%s duration=%ss",
            protocol,
            target_ip,
            port,
            duration_seconds,
        )
        result = self._ssh.run_command(cmd)
        logger.info(
            "Benign %s traffic finished exit_code=%s", protocol, result.exit_code
        )
        return BenignRunResult(
            protocol=protocol,
            exit_code=result.exit_code,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
        )
