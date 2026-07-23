"""Tool that runs benign protocol traffic and checks for false positives in the deployed rule.

This is a mandatory step in the rule validation workflow:
  deploy_rule → run_benign_traffic_check → (reject if false positive) → trigger_attacker

The tool runs legitimate traffic from the attacker host (Entity 3) towards Entity 2,
reads the IDS alert log, clears it, and returns whether the rule fired on benign traffic.
If false_positive=True the rule must be discarded — it is too generic.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agno.tools import tool

from rules_farmer.ids_monitor import IDSMonitor
from rules_farmer.tools.persistence_tools import RunContext


if TYPE_CHECKING:
    from rules_farmer.benign_traffic import BenignTrafficRunner


logger = logging.getLogger(__name__)


def make_run_benign_traffic(
    runner: "BenignTrafficRunner",
    monitor: IDSMonitor,
    context: RunContext,
):
    @tool
    def run_benign_traffic(protocol: str, sid: int, duration_seconds: float = 20.0) -> dict:
        """Run legitimate benign traffic and test whether the deployed rule fires on it (false positive check).

        Call this IMMEDIATELY AFTER deploy_rule() and BEFORE trigger_attacker().

        Workflow:
          1. Benign traffic runs from the attacker host towards the target for duration_seconds.
          2. The IDS alert log is checked for the given SID.
          3. The alert log is cleared so the real attack test starts with a clean slate.
          4. The result tells you whether the rule caught legitimate traffic.

        Decision rule:
          - false_positive=True  → rule is too generic. DISCARD it. Generate a narrower rule
            (more specific content match, higher detection_filter threshold, tighter dsize range).
          - false_positive=False → rule passed benign validation. Proceed with trigger_attacker().

        Args:
            protocol: Protocol family to generate traffic for.
                      "xrce" — XRCE-DDS legitimate participant registration and pings.
                      "mqtt" — MQTT CONNECT + PUBLISH at normal client cadence.
                      "http" — HTTP GET requests at browser-like rate.
            sid: The SID of the currently deployed rule (returned by assign_sid / deploy_rule).
            duration_seconds: How long to run benign traffic (default 20s — enough for a
                              detection_filter window to close without exceeding low thresholds).

        Returns:
            {
                "false_positive": bool,   # True → rule must be discarded
                "benign_exit_code": int,  # 0 = benign traffic ran successfully
                "stdout": str,
                "error": str              # non-empty only if the runner failed
            }
        """
        target_ip = context.fixed_destination_ip
        if not target_ip:
            logger.warning("run_benign_traffic: no fixed_destination_ip in context — skipping")
            return {
                "false_positive": False,
                "benign_exit_code": -1,
                "stdout": "",
                "error": "no fixed_destination_ip resolved for this intent",
            }

        logger.info(
            "Benign traffic check started protocol=%s sid=%s target=%s duration=%ss",
            protocol,
            sid,
            target_ip,
            duration_seconds,
        )

        error_msg = ""
        stdout_text = ""
        benign_exit_code = -1
        try:
            result = runner.run(
                protocol=protocol,
                target_ip=target_ip,
                duration_seconds=duration_seconds,
            )
            benign_exit_code = result.exit_code
            stdout_text = result.stdout
            if not result.ok:
                error_msg = result.stderr or f"benign runner exited with code {result.exit_code}"
                logger.warning("Benign traffic runner failed: %s", error_msg)
        except Exception as exc:
            error_msg = str(exc)
            logger.exception("Benign traffic runner raised exception: %s", exc)

        # Read alert log to detect false positive
        false_positive = monitor.check_fired(sid)
        logger.info(
            "Benign traffic check done protocol=%s sid=%s false_positive=%s",
            protocol,
            sid,
            false_positive,
        )

        # Record the verdict on the shared context so trigger_attacker can enforce it.
        # Only a clean run (benign traffic actually ran AND the rule stayed silent)
        # unlocks the attack. A false positive or a runner error revokes any prior pass
        # for this SID, so a rejected rule cannot slip through on a stale validation.
        if false_positive or error_msg:
            context.benign_validated_sids.discard(sid)
        else:
            context.benign_validated_sids.add(sid)

        # Always clear the log so the real attack test starts clean
        monitor.clear_alert_log()
        logger.info("Alert log cleared after benign traffic check sid=%s", sid)

        return {
            "false_positive": false_positive,
            "benign_exit_code": benign_exit_code,
            "stdout": stdout_text,
            "error": error_msg,
        }

    return run_benign_traffic
