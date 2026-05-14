from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from rules_farmer.errors import SSHUnreachableError


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int


class SSHClient:
    def __init__(
        self,
        host: str,
        user: str,
        key_path: str,
        connect_timeout: int,
        max_attempts: int = 1,
        base_delay_seconds: float = 0,
    ):
        self.host = host
        self.user = user
        self.key_path = str(Path(key_path).expanduser())
        self.connect_timeout = connect_timeout
        self.max_attempts = max_attempts
        self.base_delay_seconds = base_delay_seconds
        self._client = self._connect()

    def _connect(self):
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            logger.info(
                "SSH connect attempt host=%s user=%s attempt=%s/%s",
                self.host,
                self.user,
                attempt,
                self.max_attempts,
            )
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=self.host,
                    username=self.user,
                    key_filename=self.key_path,
                    timeout=self.connect_timeout,
                )
                logger.info("SSH connected host=%s user=%s", self.host, self.user)
                return client
            except Exception as exc:  # paramiko raises several connection exception types.
                last_error = exc
                logger.warning(
                    "SSH connect failed host=%s user=%s attempt=%s/%s error=%s",
                    self.host,
                    self.user,
                    attempt,
                    self.max_attempts,
                    exc,
                )
                if attempt < self.max_attempts:
                    time.sleep(self.base_delay_seconds * (2 ** (attempt - 1)))

        raise SSHUnreachableError(
            f"Unable to connect to {self.host} over SSH after "
            f"{self.max_attempts} attempts"
        ) from last_error

    def run_command(self, command: str) -> CommandResult:
        logger.debug(
            "SSH command start host=%s command=%s",
            self.host,
            _single_line(command),
        )
        _, stdout, stderr = self._client.exec_command(command)
        result = CommandResult(
            stdout=stdout.read().decode(),
            stderr=stderr.read().decode(),
            exit_code=stdout.channel.recv_exit_status(),
        )
        logger.debug(
            "SSH command done host=%s exit_code=%s stdout_bytes=%s stderr_bytes=%s",
            self.host,
            result.exit_code,
            len(result.stdout.encode()),
            len(result.stderr.encode()),
        )
        if result.stderr.strip():
            logger.warning(
                "SSH command stderr host=%s stderr=%s",
                self.host,
                result.stderr.strip(),
            )
        return result

def _single_line(command: str) -> str:
    return command.replace("\n", "\\n")
