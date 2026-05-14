from __future__ import annotations

import logging

from agno.tools import tool

from rules_farmer.execution_logging import log_stage
from rules_farmer.ids_rule_injector import IDSRuleInjector
from rules_farmer.ids_rule_validator import SnortRuleValidator
from rules_farmer.sid_manager import SIDManager


logger = logging.getLogger(__name__)


def make_validate_rule_syntax(validator: SnortRuleValidator):
    @tool
    def validate_rule_syntax(rule: str) -> str:
        """Validate the syntax of a single Snort 3.9.7.0 rule against the live IDS host.

        Args:
            rule: A complete Snort 3 rule. The sid:0; placeholder is accepted; SIDs are assigned later.

        Returns:
            "VALID" if syntax is accepted, otherwise "INVALID: <error details>".
        """
        log_stage("AGORA ESTA VALIDANDO A REGRA")
        logger.info("Tool validate_rule_syntax called rule=%r", rule)
        result = validator.validate(rule)
        if result.valid:
            logger.info("Tool validate_rule_syntax accepted")
            return "VALID"
        logger.warning("Tool validate_rule_syntax rejected error=%s", result.error)
        return f"INVALID: {result.error}"

    return validate_rule_syntax


def make_assign_sid(sid_manager: SIDManager):
    @tool
    def assign_sid(intent: str, rule: str) -> dict:
        """Assign a unique SID to a Snort rule. Replaces sid:0; with the real SID.

        Args:
            intent: The operator intent (used to map SID to its origin).
            rule: The Snort rule containing sid:0; placeholder.

        Returns:
            {"sid": int, "rule": "<rule with real SID>"}.
        """
        logger.info("Tool assign_sid called intent=%r", intent)
        assigned = sid_manager.assign_sids(intent, [rule])[0]
        logger.info("Tool assign_sid produced sid=%s", assigned.sid)
        return {"sid": assigned.sid, "rule": assigned.rule}

    return assign_sid


def make_deploy_rule(injector: IDSRuleInjector):
    @tool
    def deploy_rule(rule_with_sid: str) -> str:
        """Deploy a Snort rule to the IDS host and reload the Snort container.

        Args:
            rule_with_sid: The Snort rule with a real SID already assigned.

        Returns:
            "DEPLOYED" on success. Raises IDSReloadError if the container does not return to healthy.
        """
        log_stage("AGORA ESTA INJETANDO A REGRA NO IDS")
        logger.info("Tool deploy_rule called")
        injector.inject([rule_with_sid])
        logger.info("Tool deploy_rule finished")
        return "DEPLOYED"

    return deploy_rule
