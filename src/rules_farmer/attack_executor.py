from __future__ import annotations

import json
import logging
import shlex
from dataclasses import dataclass
from typing import Any

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout_json: dict[str, Any]
    container_exit_code: int
    container_stderr: str


class AttackExecutor:
    def __init__(
        self,
        ssh_client: SSHClient,
        attacks: dict[str, DiscoveredAttack],
    ):
        self.ssh_client = ssh_client
        self.attacks = attacks

    def execute(self, attack_id: str, arguments: list[str]) -> ExecutionResult:
        attack = self.attacks[attack_id]
        logger.info(
            "Attack selected attack_id=%s remote_path=%s description=%s",
            attack_id,
            attack.remote_path,
            attack.description,
        )
        logger.info(
            "Attack docker_image=%s arguments=%s",
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
        container_exit_code: int = stdout_json["exit_code"]
        remote_stderr_path: str = stdout_json["stderr_path"]

        stderr_fetch = self.ssh_client.run_command(f"cat {shlex.quote(remote_stderr_path)}")
        container_stderr = stderr_fetch.stdout.strip() if stderr_fetch.exit_code == 0 else ""

        if container_exit_code == 124:
            logger.warning(
                "Container timeout attack_id=%s timeout_seconds=%s",
                attack_id,
                self._CONTAINER_TIMEOUT_SECONDS,
            )
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

        return ExecutionResult(
            exit_code=result.exit_code,
            stdout_json=stdout_json,
            container_exit_code=container_exit_code,
            container_stderr=container_stderr,
        )

    def list_source_files(self, attack_id: str) -> list[str]:
        attack = self.attacks[attack_id]
        result = self.ssh_client.run_command(
            f"ls {shlex.quote(attack.remote_path)}"
        )
        if result.exit_code != 0:
            raise RuntimeError(f"Cannot list attack directory: {attack.remote_path}")
        return [f for f in result.stdout.splitlines() if f.strip()]

    def read_source_file(self, attack_id: str, filename: str) -> str:
        attack = self.attacks[attack_id]
        remote_path = f"{attack.remote_path}/{filename}"
        result = self.ssh_client.run_command(f"cat {shlex.quote(remote_path)}")
        if result.exit_code != 0:
            raise FileNotFoundError(f"Remote file not found: {remote_path}")
        logger.debug("Attack source file read attack_id=%s filename=%s", attack_id, filename)
        return result.stdout

    def write_source_file(self, attack_id: str, filename: str, content: str) -> None:
        attack = self.attacks[attack_id]
        remote_path = f"{attack.remote_path}/{filename}"
        self.ssh_client.write_file(remote_path, content)
        logger.info("Attack source file written attack_id=%s filename=%s", attack_id, filename)

    def rebuild_image(self, attack_id: str) -> dict[str, Any]:
        attack = self.attacks[attack_id]
        cmd = f"docker build -t {shlex.quote(attack.docker_image)} {shlex.quote(attack.remote_path)} 2>&1"
        logger.info("Docker build start attack_id=%s image=%s", attack_id, attack.docker_image)
        result = self.ssh_client.run_command(cmd)
        logger.info(
            "Docker build done attack_id=%s exit_code=%s",
            attack_id,
            result.exit_code,
        )
        return {"exit_code": result.exit_code, "output": result.stdout[:2000]}

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

    _CONTAINER_TIMEOUT_SECONDS = 60

    def _build_remote_command(
        self,
        attack: DiscoveredAttack,
        arguments: list[str],
        remote_run_dir: str,
    ) -> str:
        container_name = attack.docker_image.split(":")[0]
        docker_run = " ".join(
            [
                "docker",
                "run",
                "-d",
                "--name",
                shlex.quote(container_name),
                shlex.quote(attack.docker_image),
                *[shlex.quote(argument) for argument in arguments],
            ]
        )
        logger.info(
            "Attack docker command attack_id=%s cmd=%s",
            attack.attack_id,
            docker_run,
        )
        run_dir = shlex.quote(remote_run_dir)
        container = shlex.quote(container_name)
        timeout = self._CONTAINER_TIMEOUT_SECONDS
        return "\n".join(
            [
                "set -u",
                f"RUN_DIR={run_dir}",
                'STDOUT_PATH="$RUN_DIR/stdout.txt"',
                'STDERR_PATH="$RUN_DIR/stderr.txt"',
                f"docker rm -f {container} >/dev/null 2>&1 || true",
                f"{docker_run} >/dev/null",
                "EXIT_CODE=1",
                "set +e",
                f"CONTAINER_EXIT=$(timeout {timeout} docker wait {container})",
                "WAIT_STATUS=$?",
                "if [ $WAIT_STATUS -eq 124 ]; then",
                f"  echo 'Container exceeded {timeout}s timeout, stopping' >&2",
                f"  docker stop {container} >/dev/null 2>&1 || true",
                "  EXIT_CODE=124",
                "else",
                "  EXIT_CODE=${CONTAINER_EXIT:-1}",
                "fi",
                "set -e",
                f'docker logs {container} > "$STDOUT_PATH" 2> "$STDERR_PATH" || true',
                f"docker rm {container} >/dev/null 2>&1 || true",
                (
                    "printf "
                    "'{\"exit_code\":%s,"
                    "\"stdout_path\":\"%s\",\"stderr_path\":\"%s\"}\\n' "
                    '"$EXIT_CODE" "$STDOUT_PATH" "$STDERR_PATH"'
                ),
                'exit "$EXIT_CODE"',
            ]
        )
