from __future__ import annotations

import logging
from pathlib import Path

from agno.agent import Agent
from agno.skills import LocalSkills, Skills

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attack_executor import AttackExecutor
from rules_farmer.errors import UnmappedIntentError
from rules_farmer.execution_logging import log_stage
from rules_farmer.schemas import AttackerRequest, AttackerResult
from rules_farmer.tools import (
    make_execute_attack,
    make_list_available_attacks,
    make_read_attack_definition,
)


logger = logging.getLogger(__name__)


_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"


ATTACKER_AGENT_DESCRIPTION = """You are the Attack Agent in a Snort IDS research testbed.

For each AttackerRequest you receive:
1. Discover and pick the right attack for the operator intent.
2. Execute it against the target.
3. Return an AttackerResult describing what happened.

You have:
- Three tools (list_available_attacks, read_attack_definition, execute_attack) for live operations.
- A library of skills (browse the <skills_system> section, then call get_skill_instructions for the one you need).

Always:
- Call list_available_attacks before any final answer.
- Call execute_attack exactly once before returning.
- When request_variant=True, follow the evasion-variants skill to mutate arguments — keep the same attack_id when the intent allows.
- Copy execute_attack's container_exit_code and container_stderr into your final AttackerResult.

HARD CONSTRAINT — destination IP and port are fixed:
The AttackerRequest carries fixed_destination_ip and fixed_destination_port. These are the
testbed's well-known target service addresses (MQTT broker on 1883, XRCE-DDS Agent on 8888,
configured in config.yaml). You MUST:
- If the attack has IP/host as a required argument, set it to fixed_destination_ip — even when
  request_variant=True. NEVER mutate it across cycles.
- If the attack has port as a required argument, set it to fixed_destination_port. NEVER mutate
  the port across variants — only mutate non-destination parameters (rate, payload size, source
  port, timing, etc.).
- For attacks that do NOT accept IP or port as a parameter, treat the fixed destination as
  informational only.

If the intent does not match any discovered attack, return the closest attack_id and explain the mismatch in evasion_rationale; the orchestrator will halt if the attack_id is unknown.
"""


class AttackerAgent:
    def __init__(
        self,
        model,
        attacks: list[DiscoveredAttack],
        executor: AttackExecutor,
    ):
        self._attacks_by_id = {attack.attack_id: attack for attack in attacks}
        self._agent = Agent(
            model=model,
            description=ATTACKER_AGENT_DESCRIPTION,
            instructions=[_format_catalog(attacks)],
            skills=Skills(
                loaders=[
                    LocalSkills(str(_SKILLS_ROOT / "attacks")),
                    LocalSkills(str(_SKILLS_ROOT / "shared")),
                ]
            ),
            tools=[
                make_list_available_attacks(self._attacks_by_id),
                make_read_attack_definition(self._attacks_by_id),
                make_execute_attack(executor, self._attacks_by_id),
            ],
            output_schema=AttackerResult,
        )

    def run(self, request: AttackerRequest) -> AttackerResult:
        log_stage("AGORA O AGENTE DE ATAQUES ESTA RACIOCINANDO")
        logger.info(
            "AttackerAgent run started request_variant=%s history_count=%s",
            request.request_variant,
            len(request.variant_history),
        )
        response = self._agent.run(request.model_dump_json())
        result: AttackerResult = response.content
        if result.attack_id not in self._attacks_by_id:
            logger.error("AttackerAgent produced unknown attack_id=%s", result.attack_id)
            raise UnmappedIntentError(
                f"AttackerAgent returned unknown attack_id {result.attack_id!r}. "
                f"Available: {sorted(self._attacks_by_id)}"
            )
        logger.info(
            "AttackerAgent run finished attack_id=%s arguments=%s",
            result.attack_id,
            result.arguments,
        )
        return result


def _format_catalog(attacks: list[DiscoveredAttack]) -> str:
    lines = ["Catalog of discovered attacks (authoritative — only these attack_ids may be used):"]
    for attack in attacks:
        argument_list = ", ".join(attack.required_arguments) or "no positional arguments"
        lines.extend(
            [
                f"- attack_id: {attack.attack_id}",
                f"  description: {attack.description}",
                f"  docker_image: {attack.docker_image}",
                f"  required_arguments ({len(attack.required_arguments)}): {argument_list}",
            ]
        )
    return "\n".join(lines)
