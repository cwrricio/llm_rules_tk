from __future__ import annotations

import logging
import shlex
import time

from rules_farmer.errors import IDSReloadError
from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


class IDSRuleInjector:
    def __init__(
        self,
        ssh_client: SSHClient,
        rules_file_path: str,
        include_file_path: str,
        include_statement: str,
        container_name: str,
        poll_interval_seconds: float = 0,
        max_health_polls: int = 30,
    ):
        self.ssh_client = ssh_client
        self.rules_file_path = rules_file_path
        self.include_file_path = include_file_path
        self.include_statement = include_statement
        self.container_name = container_name
        self.poll_interval_seconds = poll_interval_seconds
        self.max_health_polls = max_health_polls

    def inject(self, rules: list[str]) -> None:
        logger.debug(
            "IDS injection started rules_file_path=%s rule_count=%s",
            self.rules_file_path,
            len(rules),
        )
        self._write_rules("\n".join(rules))
        self._ensure_rules_file_is_included()
        logger.info("Restarting IDS container container=%s", self.container_name)
        self.ssh_client.run_command(f"docker restart {shlex.quote(self.container_name)}")
        self._wait_until_running()
        logger.info("IDS injection finished container=%s", self.container_name)

    def clear_rules(self) -> None:
        logger.info("Clearing generated IDS rules rules_file_path=%s", self.rules_file_path)
        self._write_rules("")

    def _write_rules(self, content: str) -> None:
        logger.debug(
            "Writing generated IDS rules rules_file_path=%s bytes=%s",
            self.rules_file_path,
            len(content.encode()),
        )
        rules_path = shlex.quote(self.rules_file_path)
        self.ssh_client.run_command(f"cat > {rules_path} <<'EOF'\n{content}\nEOF")

    def _ensure_rules_file_is_included(self) -> None:
        logger.debug(
            "Ensuring generated rule include include_file=%s include_statement=%s",
            self.include_file_path,
            self.include_statement,
        )
        include_file = shlex.quote(self.include_file_path)
        include_statement = shlex.quote(self.include_statement)
        self.ssh_client.run_command(
            f"grep -Fxq {include_statement} {include_file} "
            f"|| printf '\\n%s\\n' {include_statement} >> {include_file}"
        )

    def _wait_until_running(self) -> None:
        container = shlex.quote(self.container_name)
        for poll in range(self.max_health_polls):
            logger.debug(
                "Polling IDS container health container=%s poll=%s/%s",
                self.container_name,
                poll + 1,
                self.max_health_polls,
            )
            result = self.ssh_client.run_command(
                f"docker inspect -f '{{{{.State.Running}}}}' {container}"
            )
            if result.exit_code == 0 and result.stdout.strip() == "true":
                logger.debug("IDS container running container=%s", self.container_name)
                return
            if poll < self.max_health_polls - 1:
                time.sleep(self.poll_interval_seconds)

        logs = self.ssh_client.run_command(f"docker logs {container}")
        logger.error("IDS container failed to become healthy container=%s", self.container_name)
        raise IDSReloadError((logs.stdout or logs.stderr).strip())
