from __future__ import annotations

import logging

from agno.tools import tool

from rules_farmer.execution_logging import log_stage
from rules_farmer.ids_monitor import IDSMonitor


logger = logging.getLogger(__name__)


def make_check_alert_fired(monitor: IDSMonitor):
    @tool
    def check_alert_fired(sid: int) -> bool:
        """Check whether the IDS alert log shows that the rule with the given SID fired.

        Reads ids_alert_log_path on the IDS host via SSH.

        Args:
            sid: The SID of the active rule to look up in the alert log.

        Returns:
            True if at least one alert for this SID is present, False otherwise.
        """
        log_stage("AGORA ESTA VERIFICANDO ALERTAS DO IDS")
        logger.info("Tool check_alert_fired called sid=%s", sid)
        fired = monitor.check_fired(sid)
        logger.info("Tool check_alert_fired finished sid=%s fired=%s", sid, fired)
        return fired

    return check_alert_fired
