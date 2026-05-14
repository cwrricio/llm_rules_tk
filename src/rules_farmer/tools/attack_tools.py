from __future__ import annotations

import logging

from agno.tools import tool

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attack_executor import AttackExecutor
from rules_farmer.execution_logging import log_stage


logger = logging.getLogger(__name__)


def make_list_available_attacks(attacks: dict[str, DiscoveredAttack]):
    @tool
    def list_available_attacks() -> list[dict]:
        """List all attacks discovered on the attacker host.

        Returns:
            List of {attack_id, description, required_arguments} for every attack available.
        """
        logger.debug("Skill list_available_attacks called count=%s", len(attacks))
        return [
            {
                "attack_id": attack.attack_id,
                "description": attack.description,
                "required_arguments": attack.required_arguments,
            }
            for attack in attacks.values()
        ]

    return list_available_attacks


def make_read_attack_definition(attacks: dict[str, DiscoveredAttack]):
    @tool
    def read_attack_definition(attack_id: str) -> dict:
        """Read the full definition of a single attack: README excerpt, docker image, required argument names.

        Args:
            attack_id: The attack identifier (must be one of those returned by list_available_attacks).

        Returns:
            {"attack_id", "description", "docker_image", "required_arguments", "readme_excerpt"} or
            {"error": "..."} if the attack_id is unknown.
        """
        logger.debug("Skill read_attack_definition called attack_id=%s", attack_id)
        attack = attacks.get(attack_id)
        if attack is None:
            return {"error": f"unknown attack_id: {attack_id}"}
        return {
            "attack_id": attack.attack_id,
            "description": attack.description,
            "docker_image": attack.docker_image,
            "required_arguments": attack.required_arguments,
            "readme_excerpt": attack.readme_excerpt,
        }

    return read_attack_definition


def make_execute_attack(executor: AttackExecutor, attacks: dict[str, DiscoveredAttack]):
    @tool
    def execute_attack(attack_id: str, arguments: list[str]) -> dict:
        """Execute an attack container on the attacker host and return the result.

        Args:
            attack_id: The attack identifier from list_available_attacks.
            arguments: Ordered positional arguments matching the entrypoint.sh usage line.

        Returns:
            {"attack_id", "arguments", "container_exit_code", "container_stderr"} on success,
            or {"error": "..."} if the attack_id is unknown or the argument count does not match.
        """
        log_stage("AGORA ESTA RODANDO O ATACANTE")
        logger.info("Tool execute_attack called attack_id=%s arguments=%s", attack_id, arguments)
        attack = attacks.get(attack_id)
        if attack is None:
            logger.error("Tool execute_attack received unknown attack_id=%s", attack_id)
            return {"error": f"unknown attack_id: {attack_id}"}
        expected = len(attack.required_arguments)
        if len(arguments) != expected:
            logger.warning(
                "Tool execute_attack argument count mismatch attack_id=%s expected=%s got=%s",
                attack_id,
                expected,
                len(arguments),
            )
            return {
                "error": (
                    f"argument count mismatch for {attack_id}: "
                    f"expected {expected} ({attack.required_arguments}), got {len(arguments)}"
                )
            }
        execution = executor.execute(attack_id, arguments)
        logger.info(
            "Tool execute_attack finished attack_id=%s container_exit_code=%s",
            attack_id,
            execution.container_exit_code,
        )
        return {
            "attack_id": attack_id,
            "arguments": arguments,
            "container_exit_code": execution.container_exit_code,
            "container_stderr": execution.container_stderr,
        }

    return execute_attack
