"""Local, self-contained adapters for the full pipeline.

The whole pipeline runs the REAL production classes. Two seams need a local
adapter because the physical testbed uses live packet capture, which is
unavailable in a self-contained/CI environment:

- ``LocalAttackExecutor`` — subclasses the real ``AttackExecutor``. It inherits
  the real source-file read/write and ``docker build`` (rebuild_image) logic
  unchanged (so the Attack Agent's mutate-source + rebuild-image loop is fully
  exercised) and only overrides ``execute()``: it runs the attack container with
  a pcap volume, then replays the produced pcap through the local Snort engine so
  the deployed rule is evaluated against the exact attack bytes.
- ``LocalBenignTrafficRunner`` — duck-typed replacement for
  ``BenignTrafficRunner``. Produces low-rate, same-protocol benign traffic as a
  pcap and replays it, so the Rules Agent's mandatory false-positive check runs
  for real.

Everything else — validator, injector, monitor, discovery, both agents, the
orchestrator, the recorders — is the untouched production code.
"""

from __future__ import annotations

import json
import logging
import shlex
import socket
import struct
from pathlib import Path

from rules_farmer.attack_executor import AttackExecutor, ExecutionResult
from rules_farmer.benign_traffic import BenignRunResult
from rules_farmer.execution_logging import log_stage
from rules_farmer.ssh import CommandResult

logger = logging.getLogger(__name__)


def replay_pcap(client, snort_container: str, pcap_name: str) -> CommandResult:
    """Replay one pcap through the deployed Snort config (read-file mode).

    Appends any matching alerts to /var/log/snort/alert_fast.txt, which the real
    IDSMonitor reads. No live capture, no privileges — identical mechanism to the
    teste mínimo.
    """
    return client.run_command(
        f"docker exec {shlex.quote(snort_container)} snort "
        "-c /etc/snort/snort.lua "
        f"-r /pcaps/{shlex.quote(pcap_name)} "
        "-k none -l /var/log/snort -A alert_fast -q"
    )


class LocalAttackExecutor(AttackExecutor):
    """AttackExecutor that runs the attack container locally and replays its pcap."""

    def __init__(
        self,
        ssh_client,
        attacks,
        *,
        snort_container: str,
        pcap_dir_host: Path,
        attack_pcap_name: str = "attack.pcap",
        container_timeout_seconds: int = 60,
    ):
        super().__init__(ssh_client=ssh_client, attacks=attacks)
        self._snort_container = snort_container
        self._pcap_dir_host = Path(pcap_dir_host)
        self._attack_pcap_name = attack_pcap_name
        self._timeout = container_timeout_seconds

    def execute(self, attack_id: str, arguments: list[str]) -> ExecutionResult:
        attack = self.attacks[attack_id]
        log_stage("AGORA ESTA EXECUTANDO O CONTAINER DE ATAQUE (LOCAL)")
        logger.info(
            "Local attack execute attack_id=%s image=%s arguments=%s",
            attack_id,
            attack.docker_image,
            arguments,
        )
        self._pcap_dir_host.mkdir(parents=True, exist_ok=True)
        # Remove a stale pcap so a failed run cannot be mistaken for a fresh one.
        (self._pcap_dir_host / self._attack_pcap_name).unlink(missing_ok=True)

        container = attack.docker_image.split(":")[0]
        run_dir = "/tmp/rules-farmer-attack"
        script = self._run_script(attack.docker_image, container, arguments, run_dir)
        result = self.ssh_client.run_command(script)
        try:
            stdout_json = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"attack runner did not return JSON (exit {result.exit_code}): "
                f"{(result.stderr or result.stdout)[:500]}"
            )
        container_exit_code = int(stdout_json["exit_code"])
        container_stderr = stdout_json.get("stderr", "")

        logger.info(
            "Local attack container finished attack_id=%s container_exit_code=%s",
            attack_id,
            container_exit_code,
        )
        if container_stderr:
            logger.info("Container stderr attack_id=%s stderr=%s", attack_id, container_stderr[:1000])

        # Replay the crafted attack pcap through the real Snort engine.
        pcap_host = self._pcap_dir_host / self._attack_pcap_name
        if pcap_host.exists():
            log_stage("REPRODUZINDO TRAFEGO DE ATAQUE NO SNORT")
            replay_pcap(self.ssh_client, self._snort_container, self._attack_pcap_name)
        else:
            logger.warning(
                "Attack produced no pcap attack_id=%s expected=%s — nothing to replay",
                attack_id,
                pcap_host,
            )

        return ExecutionResult(
            exit_code=result.exit_code,
            stdout_json=stdout_json,
            container_exit_code=container_exit_code,
            container_stderr=container_stderr,
        )

    def _run_script(self, image: str, container: str, arguments: list[str], run_dir: str) -> str:
        docker_run = " ".join(
            [
                "docker", "run", "-d", "--name", shlex.quote(container),
                "--network", "none",
                "-v", f"{shlex.quote(str(self._pcap_dir_host))}:/out",
                shlex.quote(image),
                *[shlex.quote(a) for a in arguments],
            ]
        )
        c = shlex.quote(container)
        return "\n".join(
            [
                "set -u",
                f"RUN_DIR={shlex.quote(run_dir)}",
                'mkdir -p "$RUN_DIR"',
                'STDERR_PATH="$RUN_DIR/stderr.txt"',
                f"docker rm -f {c} >/dev/null 2>&1 || true",
                f"{docker_run} >/dev/null",
                "set +e",
                f"CONTAINER_EXIT=$(timeout {self._timeout} docker wait {c})",
                "WAIT_STATUS=$?",
                "if [ $WAIT_STATUS -eq 124 ]; then",
                f"  docker stop {c} >/dev/null 2>&1 || true",
                "  EXIT_CODE=124",
                "else",
                "  EXIT_CODE=${CONTAINER_EXIT:-1}",
                "fi",
                f'docker logs {c} > "$RUN_DIR/stdout.txt" 2> "$STDERR_PATH" || true',
                f"docker rm -f {c} >/dev/null 2>&1 || true",
                "set -e",
                # Emit the same JSON contract the real executor consumes, with stderr inlined.
                'python3 - "$EXIT_CODE" "$STDERR_PATH" <<\'PY\'',
                "import json, sys",
                "exit_code = int(sys.argv[1])",
                "try:",
                "    stderr = open(sys.argv[2], encoding='utf-8', errors='replace').read().strip()",
                "except OSError:",
                "    stderr = ''",
                'print(json.dumps({"exit_code": exit_code, "stderr": stderr}))',
                "PY",
            ]
        )


class LocalBenignTrafficRunner:
    """Local benign-traffic generator: writes a low-rate benign pcap and replays it.

    Same interface as ``rules_farmer.benign_traffic.BenignTrafficRunner`` (a
    ``run(protocol, target_ip, duration_seconds, target_port)`` returning a
    ``BenignRunResult``). Benign traffic is the SAME protocol as the attack but at a
    legitimate low rate, so a rate-based rule (``track by_src``) must NOT fire on it
    while a content-only rule WILL — exactly the false positive the Rules Agent must
    design around.
    """

    def __init__(self, ssh_client, *, snort_container: str, pcap_dir_host: Path,
                 benign_pcap_name: str = "benign.pcap"):
        self._ssh = ssh_client
        self._snort_container = snort_container
        self._pcap_dir_host = Path(pcap_dir_host)
        self._benign_pcap_name = benign_pcap_name

    def run(self, protocol: str, target_ip: str, duration_seconds: float = 20.0,
            target_port: int | None = None) -> BenignRunResult:
        port = target_port or (8888 if protocol == "xrce" else 1883 if protocol == "mqtt" else 80)
        log_stage("AGORA ESTA GERANDO TRAFEGO BENIGNO (LOCAL)")
        logger.info(
            "Local benign traffic protocol=%s target=%s:%s duration=%ss",
            protocol, target_ip, port, duration_seconds,
        )
        self._pcap_dir_host.mkdir(parents=True, exist_ok=True)
        pcap_host = self._pcap_dir_host / self._benign_pcap_name
        _write_benign_pcap(pcap_host, protocol, target_ip, port)
        replay_pcap(self._ssh, self._snort_container, self._benign_pcap_name)
        return BenignRunResult(protocol=protocol, exit_code=0, stdout=(
            f"benign {protocol} traffic to {target_ip}:{port} (low rate) replayed"), stderr="")


# --------------------------------------------------------------------------- pcap
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
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    ip_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH", 0x45, 0, ip_len, 0x1234, 0, 64, 17, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    return eth + ip + udp


def _benign_profiles(protocol: str) -> list[tuple[str, bytes]]:
    """Several legitimate same-protocol payloads varying operation and size.

    A well-designed rule (content fingerprint + ``track by_src`` rate) must stay silent
    on all of these; a content-only-generic rule fires on at least one — which is the
    false positive the Rules Agent must design around. Testing against a spread of
    profiles (not one fixed packet) makes "passed the benign check" mean something.
    """
    if protocol == "xrce":
        magic = b"RTPS"
        return [
            ("ping", magic + b"\x0b\x07\x08\x00" + bytes(8)),          # ~24 B keepalive
            ("register", magic + b"\x01\x07\x28\x00" + bytes(40)),     # ~56 B participant reg
            ("heartbeat", magic + b"\x07\x07\x10\x00" + bytes(16)),    # ~32 B heartbeat
        ]
    # MQTT-ish shapes (the local replay is UDP-framed but carries realistic bytes).
    return [
        ("connect", b"\x10\x00\x04MQTT" + bytes(12)),
        ("publish", b"\x30\x11\x00\x0btest/benign" + b"hello"),
        ("subscribe", b"\x82\x10\x00\x01\x00\x0btest/benign\x00"),
    ]


def _write_benign_pcap(path: Path, protocol: str, target_ip: str, port: int) -> None:
    """Low-rate, same-protocol datagrams across several legitimate profiles.

    Each profile sends a few packets at a normal client cadence (~3 s apart), well below
    any DoS rate threshold, so a rate-based rule cannot fire on the rate while the varied
    payloads still exercise content matches.
    """
    profiles = _benign_profiles(protocol)
    frames: list[tuple[int, int, bytes]] = []
    ts = 0
    for idx, (_name, payload) in enumerate(profiles):
        sport = 51000 + idx  # distinct legitimate client per profile
        for _ in range(3):
            frame = _udp_frame("10.20.30.40", target_ip, sport, port, payload)
            frames.append((ts, 0, frame))
            ts += 3  # ~3 s between packets — normal cadence, low rate
    with path.open("wb") as f:
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_usec, frame in frames:
            f.write(struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame)
