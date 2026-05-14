from __future__ import annotations

import json
import logging
import shlex
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout_json: dict[str, Any]
    pcap_local_path: Path
    pcap_summary: str
    container_exit_code: int
    container_stderr: str


class AttackExecutor:
    def __init__(
        self,
        ssh_client: SSHClient,
        attacks: dict[str, DiscoveredAttack],
        pcap_output_dir: str | Path,
        capture_interface: str = "any",
        pcap_summarizer: Callable[[Path], str] | None = None,
    ):
        self.ssh_client = ssh_client
        self.attacks = attacks
        self.pcap_output_dir = Path(pcap_output_dir)
        self.capture_interface = capture_interface
        self.pcap_summarizer = pcap_summarizer or summarize_pcap_with_tshark

    def execute(self, attack_id: str, arguments: list[str]) -> ExecutionResult:
        attack = self.attacks[attack_id]
        logger.debug(
            "Attack executor selected attack_id=%s image=%s arguments=%s",
            attack_id,
            attack.docker_image,
            arguments,
        )
        remote_run_dir = self._create_remote_run_dir()
        logger.debug("Remote attack temp directory created path=%s", remote_run_dir)
        result = self.ssh_client.run_command(
            self._build_remote_command(
                attack=attack,
                arguments=arguments,
                remote_run_dir=remote_run_dir,
            )
        )

        logger.debug(
            "Remote attack command completed attack_id=%s exit_code=%s",
            attack_id,
            result.exit_code,
        )
        stdout_json = json.loads(result.stdout)
        remote_pcap_path = stdout_json["pcap_path"]
        container_exit_code: int = stdout_json["exit_code"]
        remote_stderr_path: str = stdout_json["stderr_path"]

        stderr_fetch = self.ssh_client.run_command(f"cat {shlex.quote(remote_stderr_path)}")
        container_stderr = stderr_fetch.stdout.strip() if stderr_fetch.exit_code == 0 else ""

        logger.info(
            "Container status attack_id=%s container_exit_code=%s stderr_lines=%s",
            attack_id,
            container_exit_code,
            len(container_stderr.splitlines()) if container_stderr else 0,
        )
        if container_stderr:
            logger.info(
                "Container stderr attack_id=%s stderr=%s",
                attack_id,
                container_stderr[:1000],
            )

        local_pcap_path = self._local_pcap_path(attack_id, remote_run_dir)
        local_pcap_path.parent.mkdir(parents=True, exist_ok=True)
        logger.debug(
            "Retrieving attack PCAP attack_id=%s remote_path=%s local_path=%s",
            attack_id,
            remote_pcap_path,
            local_pcap_path,
        )
        self.ssh_client.get_file(remote_pcap_path, local_pcap_path)
        logger.debug("Summarizing PCAP local_path=%s", local_pcap_path)
        summary = self.pcap_summarizer(local_pcap_path)
        logger.debug(
            "PCAP summary completed local_path=%s summary_bytes=%s",
            local_pcap_path,
            len(summary.encode()),
        )

        return ExecutionResult(
            exit_code=result.exit_code,
            stdout_json=stdout_json,
            pcap_local_path=local_pcap_path,
            pcap_summary=summary,
            container_exit_code=container_exit_code,
            container_stderr=container_stderr,
        )

    def _create_remote_run_dir(self) -> str:
        logger.debug("Creating remote attack temp directory")
        result = self.ssh_client.run_command("mktemp -d /tmp/rules-farmer-attack-XXXXXX")
        if result.exit_code != 0:
            logger.error(
                "Failed to create remote attack temp directory error=%s",
                (result.stderr or result.stdout).strip(),
            )
            raise RuntimeError(
                f"Unable to create remote attack temp dir: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        return result.stdout.strip()

    def _build_remote_command(
        self,
        attack: DiscoveredAttack,
        arguments: list[str],
        remote_run_dir: str,
    ) -> str:
        container_name = f"rules-farmer-{attack.attack_id}-{uuid.uuid4().hex[:8]}"
        docker_command = " ".join(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                shlex.quote(container_name),
                shlex.quote(attack.docker_image),
                *[shlex.quote(argument) for argument in arguments],
            ]
        )
        run_dir = shlex.quote(remote_run_dir)
        interface = shlex.quote(self.capture_interface)
        return "\n".join(
            [
                "set -u",
                f"RUN_DIR={run_dir}",
                'PCAP_PATH="$RUN_DIR/attack.pcap"',
                'STDOUT_PATH="$RUN_DIR/stdout.txt"',
                'STDERR_PATH="$RUN_DIR/stderr.txt"',
                f'tcpdump -i {interface} -w "$PCAP_PATH" >/dev/null 2>&1 &',
                "TCPDUMP_PID=$!",
                "sleep 1",
                "set +e",
                f'{docker_command} > "$STDOUT_PATH" 2> "$STDERR_PATH"',
                "EXIT_CODE=$?",
                "set -e",
                'kill "$TCPDUMP_PID" >/dev/null 2>&1 || true',
                'wait "$TCPDUMP_PID" >/dev/null 2>&1 || true',
                (
                    "printf "
                    "'{\"pcap_path\":\"%s\",\"exit_code\":%s,"
                    "\"stdout_path\":\"%s\",\"stderr_path\":\"%s\"}\\n' "
                    '"$PCAP_PATH" "$EXIT_CODE" "$STDOUT_PATH" "$STDERR_PATH"'
                ),
                'exit "$EXIT_CODE"',
            ]
        )

    def _local_pcap_path(self, attack_id: str, remote_run_dir: str) -> Path:
        run_name = Path(remote_run_dir).name
        return self.pcap_output_dir / f"{attack_id}-{run_name}.pcap"


def summarize_pcap_with_tshark(path: Path) -> str:
    completed = subprocess.run(
        ["tshark", "-r", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout
