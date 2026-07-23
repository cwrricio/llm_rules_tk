"""Local, SSH-free command client (see teste_minimo/local_command_client.py).

Duck-typed replacement for ``rules_farmer.ssh.SSHClient``: implements
``run_command(command) -> CommandResult`` and ``write_file(remote_path, content)``
by running everything locally via ``bash -c`` and local file writes. Point the real
production classes at it and the whole pipeline runs against local Docker — no SSH,
no remote hosts, no keys for the transport layer.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from rules_farmer.ssh import CommandResult

logger = logging.getLogger(__name__)


class LocalCommandClient:
    """Duck-typed replacement for ``rules_farmer.ssh.SSHClient`` that runs locally."""

    def __init__(self, command_timeout: int = 180):
        self.command_timeout = command_timeout

    def run_command(self, command: str) -> CommandResult:
        logger.debug("Local command start: %s", command.replace("\n", "\\n"))
        completed = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=self.command_timeout,
        )
        result = CommandResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
        )
        logger.debug(
            "Local command done exit_code=%s stdout_bytes=%s stderr_bytes=%s",
            result.exit_code,
            len(result.stdout.encode()),
            len(result.stderr.encode()),
        )
        return result

    def write_file(self, remote_path: str, content: str) -> None:
        path = Path(remote_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.debug("Local file written path=%s bytes=%s", remote_path, len(content.encode()))
