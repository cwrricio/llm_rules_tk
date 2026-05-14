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


def make_list_attack_files(executor: AttackExecutor, attacks: dict[str, DiscoveredAttack]):
    @tool
    def list_attack_files(attack_id: str) -> dict:
        """List the files in the attack directory on the attacker host.

        Call this before read_attack_source_file to discover the actual filenames
        (e.g. attack_udp_dos.c, compile.sh, Dockerfile) — do NOT guess filenames.

        Args:
            attack_id: The attack identifier.

        Returns:
            {"attack_id", "files": [filename, ...]} or {"error": "..."}.
        """
        logger.debug("Tool list_attack_files called attack_id=%s", attack_id)
        if attack_id not in attacks:
            return {"error": f"unknown attack_id: {attack_id}"}
        try:
            files = executor.list_source_files(attack_id)
        except Exception as exc:
            return {"error": str(exc)}
        return {"attack_id": attack_id, "files": files}

    return list_attack_files


def make_read_attack_source_file(executor: AttackExecutor, attacks: dict[str, DiscoveredAttack]):
    @tool
    def read_attack_source_file(attack_id: str, filename: str) -> dict:
        """Read a source file from the attack directory on the attacker host.

        Use this before modifying an attack file so you can see the current implementation.

        Args:
            attack_id: The attack identifier.
            filename: Relative filename within the attack directory (e.g. "attack.c", "entrypoint.sh").

        Returns:
            {"attack_id", "filename", "content"} or {"error": "..."}.
        """
        logger.debug("Tool read_attack_source_file called attack_id=%s filename=%s", attack_id, filename)
        if attack_id not in attacks:
            return {"error": f"unknown attack_id: {attack_id}"}
        try:
            content = executor.read_source_file(attack_id, filename)
        except FileNotFoundError as exc:
            return {"error": str(exc)}
        return {"attack_id": attack_id, "filename": filename, "content": content}

    return read_attack_source_file


def make_modify_attack_file(executor: AttackExecutor, attacks: dict[str, DiscoveredAttack]):
    @tool
    def modify_attack_file(attack_id: str, filename: str, content: str) -> dict:
        """Write new content to a source file in the attack directory on the attacker host.

        Use this to implement a file-level evasion variant when argument mutation is structurally
        impossible (e.g., only fixed destination arguments exist). After modifying one or more
        files, call rebuild_attack_image before execute_attack.

        Args:
            attack_id: The attack identifier.
            filename: Relative filename within the attack directory (e.g. "attack.c").
            content: Complete new content for the file.

        Returns:
            {"attack_id", "filename", "bytes_written"} or {"error": "..."}.
        """
        logger.info("Tool modify_attack_file called attack_id=%s filename=%s", attack_id, filename)
        if attack_id not in attacks:
            return {"error": f"unknown attack_id: {attack_id}"}
        try:
            executor.write_source_file(attack_id, filename, content)
        except Exception as exc:
            logger.error("Tool modify_attack_file failed attack_id=%s error=%s", attack_id, exc)
            return {"error": str(exc)}
        return {"attack_id": attack_id, "filename": filename, "bytes_written": len(content.encode())}

    return modify_attack_file


def make_rebuild_attack_image(executor: AttackExecutor, attacks: dict[str, DiscoveredAttack]):
    @tool
    def rebuild_attack_image(attack_id: str) -> dict:
        """Rebuild the Docker image for an attack after source files have been modified.

        Call this after modify_attack_file and before execute_attack so the container picks up
        the mutated source. Returns build output so you can confirm the build succeeded.

        Args:
            attack_id: The attack identifier.

        Returns:
            {"attack_id", "exit_code", "output"} or {"error": "..."}.
        """
        logger.info("Tool rebuild_attack_image called attack_id=%s", attack_id)
        if attack_id not in attacks:
            return {"error": f"unknown attack_id: {attack_id}"}
        result = executor.rebuild_image(attack_id)
        return {"attack_id": attack_id, **result}

    return rebuild_attack_image


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
