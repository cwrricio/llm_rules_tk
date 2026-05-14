from __future__ import annotations

import logging

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.errors import AttackPlanValidationError, UnmappedIntentError
from rules_farmer.schemas import AttackPlan, AttackerRequest


logger = logging.getLogger(__name__)


class AttackerAgent:
    def __init__(
        self,
        llm_client,
        attacks: list[DiscoveredAttack],
        max_plan_retries: int,
    ):
        self.llm_client = llm_client
        self.attacks = {attack.attack_id: attack for attack in attacks}
        self.max_plan_retries = max_plan_retries
        self.system_prompt = self._build_system_prompt(attacks)

    def run(self, request: AttackerRequest) -> AttackPlan:
        correction = None
        for attempt in range(1, self.max_plan_retries + 2):
            logger.debug(
                "Attacker agent planning attempt=%s/%s correction_present=%s",
                attempt,
                self.max_plan_retries + 1,
                correction is not None,
            )
            raw_plan = self.llm_client.generate(
                system_prompt=self.system_prompt,
                payload={
                    "request": request.model_dump(),
                    "correction": correction,
                },
                output_schema=AttackPlan,
            )
            plan = AttackPlan.model_validate(raw_plan)
            correction = self._validate(plan)
            if correction is None:
                logger.debug(
                    "Attacker agent produced valid plan attack_id=%s arguments=%s",
                    plan.attack_id,
                    plan.arguments,
                )
                return plan
            logger.warning("Attacker agent plan rejected correction=%s", correction)

        logger.error("Attacker agent exhausted plan retries last_correction=%s", correction)
        raise AttackPlanValidationError(
            f"Invalid argument list for {correction['attack_id']}: "
            f"expected {correction['expected_count']}, got {correction['actual_count']}"
        )

    def _validate(self, plan: AttackPlan) -> dict[str, str] | None:
        attack = self.attacks.get(plan.attack_id)
        if attack is None:
            logger.error("Attacker agent selected unmapped attack_id=%s", plan.attack_id)
            raise UnmappedIntentError(f"No discovered attack matches {plan.attack_id}")

        expected_count = len(attack.required_arguments)
        actual_count = len(plan.arguments)
        if actual_count != expected_count:
            return {
                "attack_id": plan.attack_id,
                "field": "arguments",
                "expected_count": str(expected_count),
                "actual_count": str(actual_count),
            }
        return None

    def _build_system_prompt(self, attacks: list[DiscoveredAttack]) -> str:
        lines = [
            "Select exactly one discovered attack and produce an AttackPlan.",
            "Use only attack_id values listed below.",
            "Fill arguments as an ordered list matching the entrypoint.sh usage.",
            "Generate evasion_rationale before execution as a pre-hypothesis.",
            "If no discovered attack matches the operator intent, use the closest attack_id only if it is defensible from README context; otherwise return an unmapped attack_id so deterministic validation halts.",
            "Discovered attacks:",
        ]
        for attack in attacks:
            arguments = ", ".join(attack.required_arguments) or "no positional arguments"
            lines.extend(
                [
                    f"- attack_id: {attack.attack_id}",
                    f"  description: {attack.description}",
                    f"  docker_image: {attack.docker_image}",
                    f"  required_arguments: {arguments}",
                    f"  readme_excerpt: {attack.readme_excerpt}",
                ]
            )
        return "\n".join(lines)
