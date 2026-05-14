from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agno.tools import tool

from rules_farmer.execution_logging import log_stage
from rules_farmer.schemas import AttackerRequest, VariantResult
from rules_farmer.tools.persistence_tools import RunContext


if TYPE_CHECKING:
    from rules_farmer.agents.attacker_agent import AttackerAgent


logger = logging.getLogger(__name__)


def make_trigger_attacker(attacker_agent: "AttackerAgent", context: RunContext):
    @tool
    def trigger_attacker(
        intent: str,
        rule: str,
        sid: int,
        request_variant: bool,
        previous_attacks: list[dict] | None = None,
    ) -> dict:
        """Invoke the Attack Agent to pick an attack and execute it against the target.

        The destination IP and port are FIXED by config and resolved from the intent at experiment
        startup. They are injected automatically into the AttackerRequest — the Attack Agent
        receives them and MUST keep them unchanged across base and variant cycles. Do not pass
        them as arguments to this tool.

        Use request_variant=False for the first attack of an experiment.
        Use request_variant=True after a rule has already detected a previous attack, to ask
        the Attack Agent to produce an evasion variant.

        Args:
            intent: The operator intent for context.
            rule: The currently deployed Snort rule (lets the attack agent reason about evasion).
            sid: The active SID (for context only; the attack agent does not use it directly).
            request_variant: True to ask for an evasion variant of the previous attack.
            previous_attacks: List of {attack_id, arguments, fired} from earlier attempts.

        Returns:
            {"attack_id", "arguments", "evasion_rationale", "container_exit_code", "container_stderr"}.
        """
        history = [
            VariantResult(
                attack_id=item["attack_id"],
                arguments=item.get("arguments", []),
                fired=item.get("fired", False),
            )
            for item in (previous_attacks or [])
        ]
        request = AttackerRequest(
            intent=intent,
            rule=rule,
            sid=sid,
            request_variant=request_variant,
            variant_history=history,
            fixed_destination_ip=context.fixed_destination_ip,
            fixed_destination_port=context.fixed_destination_port,
        )
        log_stage("AGORA ESTA PLANEJANDO O ATAQUE")
        logger.info(
            "Tool trigger_attacker invoked request_variant=%s history_count=%s fixed_destination=%s:%s",
            request_variant,
            len(history),
            context.fixed_destination_ip,
            context.fixed_destination_port,
        )
        result = attacker_agent.run(request)
        logger.info(
            "Tool trigger_attacker finished attack_id=%s arguments=%s",
            result.attack_id,
            result.arguments,
        )
        return result.model_dump()

    return trigger_attacker
