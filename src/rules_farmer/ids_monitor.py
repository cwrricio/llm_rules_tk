from __future__ import annotations

import logging
import re
import shlex

from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


class IDSMonitor:
    def __init__(self, ssh_client: SSHClient, alert_log_path: str):
        self.ssh_client = ssh_client
        self.alert_log_path = alert_log_path

    def check_fired(self, sid: int) -> bool:
        logger.debug("Reading IDS alert log path=%s sid=%s", self.alert_log_path, sid)
        result = self.ssh_client.run_command(f"cat {shlex.quote(self.alert_log_path)}")
        if result.exit_code != 0 or not result.stdout:
            logger.info(
                "IDS alert log empty or unavailable sid=%s exit_code=%s",
                sid,
                result.exit_code,
            )
            return False

        fired = bool(
            re.search(rf"\[\d+:{sid}:\d+\]", result.stdout)
            or re.search(rf"\bsid\s*:\s*{sid}\s*;", result.stdout)
        )
        logger.info("IDS alert log checked sid=%s fired=%s", sid, fired)
        return fired

    def clear_alert_log(self) -> None:
        logger.info("Clearing IDS alert log path=%s", self.alert_log_path)
        self.ssh_client.run_command(f"truncate -s 0 {shlex.quote(self.alert_log_path)}")
