from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agno.tools import tool

from rules_farmer.execution_logging import log_stage
from rules_farmer.schemas import AttackerRequest, VariantResult
from rules_farmer.tools.persistence_tools import RunContext


if TYPE_CHECKING:
    from rules_farmer.agents.attacker_agent import AttackerAgent
    from rules_farmer.mutation_recorder import MutationContext


logger = logging.getLogger(__name__)


def make_trigger_attacker(
    attacker_agent: "AttackerAgent",
    context: RunContext,
    mutation_context: "MutationContext | None" = None,
):
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
            On a skipped/failed benign check it instead returns {"error": "benign_check_required", ...}
            and does NOT run the attack — call run_benign_traffic(protocol, sid) first.
        """
        # Hard gate: never attack with a rule that has not cleared the benign
        # false-positive check. The prompt already forbids skipping run_benign_traffic,
        # but relying on prompt discipline let a hallucinated flow attack an unvalidated
        # rule. This makes the guarantee structural.
        if sid not in context.benign_validated_sids:
            logger.warning(
                "trigger_attacker refused: sid=%s has not passed run_benign_traffic "
                "(validated=%s)",
                sid,
                sorted(context.benign_validated_sids),
            )
            return {
                "error": "benign_check_required",
                "message": (
                    f"Rule SID {sid} has not passed the benign false-positive check. "
                    f"Call run_benign_traffic(protocol, sid={sid}) and only proceed if it "
                    f"returns false_positive=False. If it returned false_positive=True, "
                    f"discard the rule and generate a narrower one."
                ),
                "attack_id": None,
                "arguments": [],
                "evasion_rationale": "",
                "container_exit_code": None,
                "container_stderr": "",
            }

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
        if mutation_context is not None:
            mutation_context.experiment_id = context.experiment_id
            mutation_context.variant_label = context.variant_label
        result = attacker_agent.run(request)
        logger.info(
            "Tool trigger_attacker finished attack_id=%s arguments=%s",
            result.attack_id,
            result.arguments,
        )
        return result.model_dump()

    return trigger_attacker
